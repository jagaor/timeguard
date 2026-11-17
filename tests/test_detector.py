import pytest
from datetime import datetime, timezone
from src.detector import detect_anomaly, AnomalyRecord
from src.policy import match_policy, load_policies
from src.parser import enrich_event
from src.models import EnrichedEvent, Event, Policy


def test_event_within_window(within_window_event):
    """Evento dentro de la ventana aprobada no debe generar anomalía."""
    result = detect_anomaly(within_window_event)
    assert result is None


def test_event_outside_window_weekend(weekend_event):
    """Evento en fin de semana fuera de ventana debe tener score alto y factor de riesgo."""
    record = detect_anomaly(weekend_event)
    assert isinstance(record, AnomalyRecord)
    assert record.risk_score >= 60
    assert "Acceso en fin de semana" in record.risk_factors


def test_event_nocturno_critical(nocturnal_sudo_event):
    """Evento SUDO nocturno fuera de ventana debe ser CRITICAL y score > 70."""
    record = detect_anomaly(nocturnal_sudo_event)
    assert record.alert_level == "CRITICAL"
    assert record.risk_score > 70


def test_policy_match_glob(policies):
    """match_policy debe resolver patrones glob en account_pattern."""
    policy = match_policy("svc_backup_prod", policies)
    assert policy is not None
    assert policy.account_pattern == "svc_backup*"


def test_policy_no_match(policies):
    """match_policy debe devolver None si no hay coincidencia."""
    assert match_policy("unknown_account", policies) is None


def test_enrich_timezone():
    """La hora local debe ajustarse a la zona horaria de la política (invierno UTC+1)."""
    event = Event(
        account="user1",
        event_type="LOGIN",
        timestamp=datetime(2024, 1, 15, 6, 0, tzinfo=timezone.utc),
        source_ip="10.0.0.1",
        session_id="sess-1",
    )
    policy = Policy(
        account_pattern="user1",
        allowed_hours={"start": "08:00", "end": "20:00"},
        allowed_days=["Mon", "Tue", "Wed", "Thu", "Fri"],
        timezone="Europe/Madrid",
        risk_level="MEDIUM",
    )
    enriched = enrich_event(event, policy)
    assert enriched.hour_local == 7


def test_deviation_minutes(outside_window_event):
    """La desviación en minutos debe calcularse desde el fin de la ventana."""
    # Evento a las 23:00, ventana hasta 20:00 -> desviación >= 180 minutos
    assert outside_window_event.deviation_minutes >= 180
