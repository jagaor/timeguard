#!/usr/bin/env python3
"""Punto de entrada CLI de TimeGuard.

Autor: Javier Garrido Ortiz

Subcomandos disponibles:
  scan    Ingesta logs, evalúa políticas, detecta anomalías y persiste alertas.
  serve   Arranca la API REST FastAPI con uvicorn.
  report  Muestra un resumen de las alertas almacenadas con Rich.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel

console = Console()


def _print_banner() -> None:
    """Muestra el banner de bienvenida de TimeGuard."""
    console.print(
        Panel.fit(
            "[bold cyan]TimeGuard[/bold cyan]\n"
            "[dim]ITDR basado en análisis temporal de cuentas privilegiadas[/dim]",
            border_style="cyan",
        )
    )


def scan_command(args: argparse.Namespace) -> int:
    """Ejecuta el pipeline completo de detección sobre un fichero de logs."""
    # Importación diferida para que 'report' y 'serve' no carguen dependencias pesadas
    from ingestor import load_events
    from parser import enrich_events
    from policy import PolicyEngine
    from detector import Detector
    from storage import AlertStore
    from alerter import render_alerts_table

    input_path = Path(args.input)
    policies_path = Path(args.policies)
    db_path = Path(args.output_db)

    if not input_path.is_file():
        console.print(f"[red]Error:[/red] no existe el fichero de logs {input_path}")
        return 2
    if not policies_path.is_file():
        console.print(f"[red]Error:[/red] no existe el fichero de políticas {policies_path}")
        return 2

    console.print(f"Cargando eventos desde [bold]{input_path}[/bold] (formato={args.format})")
    events = load_events(input_path, fmt=args.format)
    console.print(f"Eventos normalizados: [bold]{len(events)}[/bold]")

    engine = PolicyEngine.from_yaml(policies_path)
    enriched = enrich_events(events, engine)

    detector = Detector(engine)
    alerts = detector.detect(enriched)
    console.print(f"Alertas generadas: [bold]{len(alerts)}[/bold]")

    store = AlertStore(db_path)
    store.init_schema()
    inserted = store.save_alerts(alerts)
    console.print(f"Alertas persistidas en [bold]{db_path}[/bold]: {inserted}")

    if args.report and alerts:
        render_alerts_table(console, alerts)

    return 0


def serve_command(args: argparse.Namespace) -> int:
    """Arranca el servidor FastAPI con uvicorn."""
    import uvicorn

    console.print(f"Arrancando API en http://{args.host}:{args.port}")
    uvicorn.run("api:app", host=args.host, port=args.port, reload=False)
    return 0


def report_command(args: argparse.Namespace) -> int:
    """Muestra un resumen de alertas almacenadas en SQLite."""
    from storage import AlertStore
    from alerter import render_alerts_table, render_stats_summary

    db_path = Path(args.db)
    if not db_path.is_file():
        console.print(f"[red]Error:[/red] no existe la base de datos {db_path}")
        return 2

    store = AlertStore(db_path)
    stats = store.stats()
    render_stats_summary(console, stats)

    alerts = store.recent_alerts(limit=args.last_n)
    if alerts:
        render_alerts_table(console, alerts)
    else:
        console.print("[yellow]No hay alertas registradas.[/yellow]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construye el parser de argumentos con los tres subcomandos."""
    parser = argparse.ArgumentParser(
        prog="timeguard",
        description="Detección de accesos privilegiados fuera de ventana temporal.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Ingesta logs y detecta anomalías temporales")
    p_scan.add_argument("--input", required=True, help="Ruta al fichero JSON o CSV de logs")
    p_scan.add_argument("--policies", required=True, help="Ruta al YAML de políticas")
    p_scan.add_argument("--output-db", default="timeguard.db", help="Ruta SQLite de salida")
    p_scan.add_argument("--report", action="store_true", help="Imprime tabla Rich al finalizar")
    p_scan.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Formato del fichero de entrada (por defecto json)",
    )
    p_scan.set_defaults(func=scan_command)

    p_serve = sub.add_parser("serve", help="Arranca la API REST FastAPI")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host de escucha")
    p_serve.add_argument("--port", type=int, default=8000, help="Puerto de escucha")
    p_serve.set_defaults(func=serve_command)

    p_report = sub.add_parser("report", help="Resumen de alertas almacenadas")
    p_report.add_argument("--db", default="timeguard.db", help="Ruta SQLite de lectura")
    p_report.add_argument("--last-n", type=int, default=20, help="Número de alertas a mostrar")
    p_report.set_defaults(func=report_command)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Punto de entrada principal: parsea args y delega al subcomando."""
    _print_banner()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("[yellow]Interrumpido por el usuario.[/yellow]")
        return 130
    except Exception as exc:  # pragma: no cover - salvaguarda de CLI
        console.print(f"[red]Error inesperado:[/red] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
