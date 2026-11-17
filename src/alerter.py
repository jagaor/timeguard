import json
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from src.detector import AnomalyRecord


COLOR_BY_LEVEL = {
    "CRITICAL": "red",
    "WARNING": "yellow",
    "INFO": "blue",
}


def _severity_color(level: str) -> str:
    return COLOR_BY_LEVEL.get(level.upper(), "white")


def build_summary(anomalies: list[AnomalyRecord], total: int) -> dict[str, Any]:
    """Construye un resumen apto para el endpoint /api/v1/stats."""
    distribution: dict[str, int] = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}
    for anomaly in anomalies:
        level = anomaly.level.upper()
        distribution[level] = distribution.get(level, 0) + 1

    return {
        "total_events": total,
        "total_anomalies": len(anomalies),
        "distribution": distribution,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def print_report(anomalies: list[AnomalyRecord], total_events: int) -> None:
    """Imprime por consola el resumen y la tabla detallada de anomalías."""
    console = Console()
    summary = build_summary(anomalies, total_events)

    summary_text = Text()
    summary_text.append(f"Eventos analizados: {summary['total_events']}\n", style="bold")
    summary_text.append(f"Anomalías detectadas: {summary['total_anomalies']}\n", style="bold")
    summary_text.append("Distribución por nivel:\n", style="bold")
    for level, count in summary["distribution"].items():
        summary_text.append(f"  {level}: {count}\n", style=_severity_color(level))

    console.print(
        Panel(
            summary_text,
            title="[bold cyan]TimeGuard - Resumen del análisis[/bold cyan]",
            border_style="cyan",
        )
    )

    if not anomalies:
        console.print("[green]No se han detectado anomalías.[/green]")
        return

    table = Table(title="Anomalías detectadas", show_lines=True)
    table.add_column("Cuenta", style="bold")
    table.add_column("Tipo de evento")
    table.add_column("Timestamp (UTC)")
    table.add_column("Desviación (min)", justify="right")
    table.add_column("Score", justify="right")
    table.add_column("Nivel")

    for anomaly in anomalies:
        color = _severity_color(anomaly.level)
        table.add_row(
            anomaly.account,
            anomaly.event_type,
            anomaly.timestamp.isoformat() if isinstance(anomaly.timestamp, datetime) else str(anomaly.timestamp),
            f"{anomaly.deviation_minutes:.1f}",
            f"{anomaly.score:.1f}",
            Text(anomaly.level.upper(), style=color),
        )

    console.print(table)


def export_report(anomalies: list[AnomalyRecord], out_path: str) -> None:
    """Serializa las anomalías a JSON con indentación y fechas ISO."""
    serializable = []
    for anomaly in anomalies:
        record = anomaly.model_dump() if hasattr(anomaly, "model_dump") else dict(anomaly)
        for key, value in record.items():
            if isinstance(value, datetime):
                record[key] = value.isoformat()
        serializable.append(record)

    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(serializable, indent=2, ensure_ascii=False), encoding="utf-8")

    console = Console()
    console.print(f"[dim]Reporte exportado en: {path.resolve()}[/dim]")
