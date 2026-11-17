"""API REST de TimeGuard.

Expone las alertas persistidas, estadísticas agregadas y permite lanzar
un scan completo del pipeline bajo demanda. La conexión a SQLite se
abre y cierra por request mediante un dependency de FastAPI.
"""
from __future__ import annotations

import os
from typing import Any, Iterator

from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from src import detector, ingestor, parser, policy, storage

DB_PATH = os.environ.get("TIMEGUARD_DB_PATH", "timeguard.db")

app = FastAPI(title="TimeGuard API", version="1.0.0")


class ScanRequest(BaseModel):
    """Cuerpo del POST /api/v1/scan."""

    log_path: str = Field(..., description="Ruta al fichero de logs (JSON o CSV)")
    policies_path: str = Field(..., description="Ruta al fichero YAML de políticas")


class ScanResponse(BaseModel):
    """Respuesta del scan completo."""

    scanned: int
    anomalies: int
    report_path: str


def get_db() -> Iterator[Any]:
    """Dependency que abre y cierra la conexión SQLite por request."""
    conn = storage.connect(DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


@app.get("/health")
def health() -> dict[str, str]:
    """Comprobación de vida del servicio."""
    return {"status": "ok", "version": app.version}


@app.get("/api/v1/alerts")
def list_alerts(
    limit: int = Query(50, ge=1, le=1000, description="Máximo de alertas a devolver"),
    level: str | None = Query(None, description="Filtro por nivel de severidad"),
    db: Any = Depends(get_db),
) -> list[dict[str, Any]]:
    """Devuelve las alertas persistidas, opcionalmente filtradas por nivel."""
    anomalies = storage.get_anomalies(db, limit=limit, level=level)
    return [dict(a) for a in anomalies]


@app.get("/api/v1/stats")
def get_stats(db: Any = Depends(get_db)) -> dict[str, Any]:
    """Resumen agregado de alertas por nivel, cuenta y contexto temporal."""
    return storage.get_stats(db)


@app.post("/api/v1/scan", response_model=ScanResponse)
def run_scan(payload: ScanRequest, db: Any = Depends(get_db)) -> ScanResponse:
    """Ejecuta el pipeline completo y persiste las anomalías detectadas.

    Pasos: ingesta de logs, extracción de metadatos temporales, evaluación
    de políticas, detección de desviaciones y persistencia en SQLite.
    """
    try:
        events = ingestor.load_events(payload.log_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Log no encontrado: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Formato de log inválido: {exc}") from exc

    try:
        policies = policy.load_policies(payload.policies_path)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=f"Políticas no encontradas: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Políticas inválidas: {exc}") from exc

    enriched = parser.enrich_events(events, policies)
    evaluated = policy.evaluate_events(enriched, policies)
    anomalies = detector.detect(evaluated)

    report_path = storage.persist_anomalies(db, anomalies)

    return ScanResponse(
        scanned=len(events),
        anomalies=len(anomalies),
        report_path=report_path,
    )
