import logging
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import httpx
import pandas as pd
from pydantic import BaseModel, Field, ValidationError, field_validator

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAIL = "LOGIN_FAIL"
    SUDO = "SUDO"
    SESSION_OPEN = "SESSION_OPEN"
    SESSION_CLOSE = "SESSION_CLOSE"
    PRIVILEGE_USE = "PRIVILEGE_USE"


class EventModel(BaseModel):
    account: str
    event_type: EventType
    timestamp: datetime
    source_ip: str = Field(default="0.0.0.0")
    session_id: str = Field(default="")

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_utc(cls, value: Any) -> Any:
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


def load_events(path: str, fmt: str) -> list[dict]:
    """Carga eventos desde un fichero JSON o CSV y devuelve una lista de dicts."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"No se encontró el fichero de eventos: {path}")

    fmt = fmt.lower().strip()
    if fmt == "json":
        import json

        with file_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, list):
            raise ValueError("El fichero JSON debe contener una lista de objetos")
        return data

    if fmt == "csv":
        df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
        expected = {"account", "event_type", "timestamp", "source_ip", "session_id"}
        missing = expected.difference(df.columns)
        if missing:
            raise ValueError(f"Faltan columnas obligatorias en CSV: {sorted(missing)}")
        return df.to_dict(orient="records")

    raise ValueError(f"Formato no soportado: {fmt}. Use 'json' o 'csv'.")


def normalize_event(raw: dict) -> EventModel:
    """Normaliza un dict crudo a EventModel. Lanza ValidationError si es inválido."""
    return EventModel.model_validate(raw)


def fetch_from_mock(base_url: str) -> list[dict]:
    """Obtiene la lista de eventos desde el mock server HTTP."""
    url = f"{base_url.rstrip('/')}/api/mock/events"
    with httpx.Client(timeout=10.0) as client:
        response = client.get(url)
        response.raise_for_status()
        payload = response.json()
    if isinstance(payload, dict) and "events" in payload:
        payload = payload["events"]
    if not isinstance(payload, list):
        raise ValueError("Respuesta inesperada del mock server: se esperaba una lista")
    return payload


def ingest(path: str | None = None, fmt: str = "json", base_url: str | None = None) -> list[EventModel]:
    """Punto de entrada de alto nivel: carga, normaliza y descarta eventos inválidos."""
    if base_url:
        raw_events = fetch_from_mock(base_url)
    elif path:
        raw_events = load_events(path, fmt)
    else:
        raise ValueError("Debe indicarse 'path' o 'base_url'")

    events: list[EventModel] = []
    for idx, raw in enumerate(raw_events):
        try:
            events.append(normalize_event(raw))
        except ValidationError as exc:
            logger.warning("Evento %d descartado por validación: %s", idx, exc.errors())
    return events
