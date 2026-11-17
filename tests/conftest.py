import pytest
from datetime import datetime, timezone
from pathlib import Path

from src.policy import PolicyModel, load_policies
from src.ingestor import EventModel


@pytest.fixture
def policy_model() -> PolicyModel:
    """Política de ejemplo para la cuenta adm_deploy."""
    return PolicyModel(
        account_pattern="adm_deploy",
        allowed_days=["Mon", "Tue", "Wed", "Thu", "Fri"],
        allowed_hours_start=8,
        allowed_hours_end=20,
        timezone="Europe/Madrid",
        risk_level="HIGH",
    )


@pytest.fixture
def event_inside_window() -> EventModel:
    """Evento de adm_deploy un miércoles a las 10:30 UTC (11:30 Madrid), dentro de ventana."""
    return EventModel(
        account="adm_deploy",
        event_type="login",
        timestamp=datetime(2025, 6, 11, 10, 30, tzinfo=timezone.utc),  # miércoles
        source_ip="192.0.2.10",
        session_id="sess-inside-001",
    )


@pytest.fixture
def event_outside_window() -> EventModel:
    """Evento de adm_deploy un sábado a las 03:17 UTC, fuera de ventana."""
    return EventModel(
        account="adm_deploy",
        event_type="login",
        timestamp=datetime(2025, 6, 14, 3, 17, tzinfo=timezone.utc),  # sábado
        source_ip="198.51.100.23",
        session_id="sess-outside-002",
    )


@pytest.fixture
def sample_policies() -> list[PolicyModel]:
    """Carga las políticas reales desde config/policies.yaml."""
    config_path = Path(__file__).parent.parent / "config" / "policies.yaml"
    return load_policies(str(config_path))