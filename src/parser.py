import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import Field

from src.ingestor import EventModel
from src.policy import PolicyModel

logger = logging.getLogger(__name__)

# Festivos estáticos en formato YYYY-MM-DD (España, 2025-2027)
HOLIDAYS: dict[str, str] = {
    "2025-01-01": "Año Nuevo",
    "2025-01-06": "Epifanía",
    "2025-04-18": "Viernes Santo",
    "2025-05-01": "Día del Trabajador",
    "2025-08-15": "Asunción",
    "2025-10-12": "Fiesta Nacional",
    "2025-11-01": "Todos los Santos",
    "2025-12-06": "Constitución",
    "2025-12-08": "Inmaculada",
    "2025-12-25": "Navidad",
    "2026-01-01": "Año Nuevo",
    "2026-01-06": "Epifanía",
    "2026-04-03": "Viernes Santo",
    "2026-05-01": "Día del Trabajador",
    "2026-08-15": "Asunción",
    "2026-10-12": "Fiesta Nacional",
    "2026-11-01": "Todos los Santos",
    "2026-12-06": "Constitución",
    "2026-12-08": "Inmaculada",
    "2026-12-25": "Navidad",
    "2027-01-01": "Año Nuevo",
    "2027-01-06": "Epifanía",
    "2027-03-26": "Viernes Santo",
    "2027-05-01": "Día del Trabajador",
    "2027-08-15": "Asunción",
    "2027-10-12": "Fiesta Nacional",
    "2027-11-01": "Todos los Santos",
    "2027-12-06": "Constitución",
    "2027-12-08": "Inmaculada",
    "2027-12-25": "Navidad",
}

_WEEKDAY_NAMES = [
    "Monday", "Tuesday", "Wednesday", "Thursday",
    "Friday", "Saturday", "Sunday",
]


class EnrichedEvent(EventModel):
    """Evento de acceso enriquecido con metadatos temporales."""

    local_dt: datetime = Field(..., description="Timestamp ajustado a la timezone de la política")
    weekday_name: str = Field(..., description="Nombre del día de la semana en inglés")
    hour_local: int = Field(..., ge=0, le=23, description="Hora local (0-23)")
    is_weekend: bool = Field(..., description="True si cae en sábado o domingo")
    is_holiday: bool = Field(..., description="True si cae en festivo")
    is_within_window: bool = Field(..., description="True si está dentro de la ventana aprobada")


def _resolve_tz(tz_name: str) -> ZoneInfo:
    """Resuelve la zona horaria, cayendo a UTC si no es válida."""
    try:
        return ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError):
        logger.warning("Timezone '%s' no válida, usando UTC", tz_name)
        return ZoneInfo("UTC")


def _is_within_window(hour_local: int, weekday_name: str, policy: PolicyModel) -> bool:
    """Comprueba si la hora y el día caen dentro de la ventana aprobada."""
    if weekday_name not in policy.allowed_days:
        return False
    start_h, start_m = policy.allowed_hours.start
    end_h, end_m = policy.allowed_hours.end
    minutes = hour_local * 60
    # Ventana que cruza medianoche (ej. 22:00-06:00)
    if (start_h, start_m) <= (end_h, end_m):
        return start_h * 60 + start_m <= minutes < end_h * 60 + end_m
    return minutes >= start_h * 60 + start_m or minutes < end_h * 60 + end_m


def enrich_event(event: EventModel, policy: PolicyModel) -> EnrichedEvent:
    """Enriquece un evento con metadatos temporales según la política aplicada."""
    tz = _resolve_tz(policy.timezone)
    ts = event.timestamp
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    local_dt = ts.astimezone(tz)
    weekday_name = _WEEKDAY_NAMES[local_dt.weekday()]
    hour_local = local_dt.hour
    is_weekend = local_dt.weekday() >= 5
    is_holiday = local_dt.strftime("%Y-%m-%d") in HOLIDAYS
    within = _is_within_window(hour_local, weekday_name, policy)

    return EnrichedEvent(
        **event.model_dump(),
        local_dt=local_dt,
        weekday_name=weekday_name,
        hour_local=hour_local,
        is_weekend=is_weekend,
        is_holiday=is_holiday,
        is_within_window=within,
    )


def calc_deviation_minutes(event: EnrichedEvent, policy: PolicyModel) -> int:
    """Devuelve los minutos fuera de la ventana más cercana (0 si está dentro)."""
    if event.is_within_window:
        return 0

    local_dt = event.local_dt
    start_h, start_m = policy.allowed_hours.start
    end_h, end_m = policy.allowed_hours.end

    # Construir el inicio y fin de la ventana para el día del evento
    day_start = local_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    window_start = day_start + timedelta(hours=start_h, minutes=start_m)
    window_end = day_start + timedelta(hours=end_h, minutes=end_m)
    if window_end <= window_start:
        window_end += timedelta(days=1)

    if local_dt < window_start:
        delta = window_start - local_dt
    else:
        delta = local_dt - window_end

    return max(0, int(delta.total_seconds() // 60))
