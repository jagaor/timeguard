import logging
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from src.parser import EnrichedEvent

logger = logging.getLogger(__name__)


class AnomalyRecord(BaseModel):
    """Registro de anomalía detectada con su scoring y factores de riesgo."""
    account: str
    event_type: str
    timestamp_utc: datetime
    local_dt: datetime
    deviation_minutes: int
    risk_score: int = Field(..., ge=0, le=100)
    risk_factors: list[str]
    policy_description: str
    alert_level: str


# Pesos de scoring (puntos)
BASE_OUT_OF_WINDOW = 20
WEEKEND_POINTS = 20
NIGHT_POINTS = 20
HOLIDAY_POINTS = 15
LONG_DEVIATION_POINTS = 15
PRIVILEGE_EVENT_POINTS = 10


def _score_to_level(score: int) -> str:
    """Mapea el score numérico a nivel de alerta."""
    if score < 40:
        return "INFO"
    if score <= 70:
        return "WARNING"
    return "CRITICAL"


def detect_anomaly(event: EnrichedEvent, deviation_minutes: int) -> Optional[AnomalyRecord]:
    """
    Evalúa un evento enriquecido y devuelve un AnomalyRecord si está fuera de la ventana.

    Args:
        event: Evento enriquecido con metadatos temporales y de política.
        deviation_minutes: Minutos de desviación respecto a la ventana aprobada.

    Returns:
        AnomalyRecord o None si el evento está dentro de la ventana.
    """
    if event.is_within_window:
        return None

    score = BASE_OUT_OF_WINDOW
    factors: list[str] = ["Acceso fuera de la ventana horaria aprobada"]

    if event.is_weekend:
        score += WEEKEND_POINTS
        factors.append("Acceso en fin de semana")

    local_hour = event.local_dt.hour
    if 0 <= local_hour < 6:
        score += NIGHT_POINTS
        factors.append(f"Horario nocturno {event.local_dt.strftime('%H:%M')}")

    if event.is_holiday:
        score += HOLIDAY_POINTS
        factors.append("Acceso en día festivo")

    if deviation_minutes > 120:
        score += LONG_DEVIATION_POINTS
        factors.append(f"Desviación elevada de {deviation_minutes} minutos")

    if event.event_type in ("SUDO", "PRIVILEGE_USE"):
        score += PRIVILEGE_EVENT_POINTS
        factors.append(f"Evento privilegiado: {event.event_type}")

    risk_score = min(score, 100)
    alert_level = _score_to_level(risk_score)

    logger.debug(
        "Anomalía detectada para %s: score=%d nivel=%s",
        event.account,
        risk_score,
        alert_level,
    )

    return AnomalyRecord(
        account=event.account,
        event_type=event.event_type,
        timestamp_utc=event.timestamp_utc,
        local_dt=event.local_dt,
        deviation_minutes=deviation_minutes,
        risk_score=risk_score,
        risk_factors=factors,
        policy_description=event.policy_description,
        alert_level=alert_level,
    )
