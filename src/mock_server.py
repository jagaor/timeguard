import os
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
import uvicorn

app = FastAPI(title="TimeGuard Mock Server", version="1.0.0")

# Fecha base: lunes 2025-01-06 00:00 UTC
BASE = datetime(2025, 1, 6, tzinfo=timezone.utc)

def _ts(day_offset: int, hour: int, minute: int = 0) -> str:
    """Genera timestamp ISO 8601 UTC a partir de offset de días y hora."""
    dt = BASE + timedelta(days=day_offset, hours=hour, minutes=minute)
    return dt.isoformat()

# 30 eventos sintéticos con anomalías temporales deliberadas
MOCK_EVENTS = [
    # Lunes 6
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(0, 2, 0), "source_ip": "192.168.1.10", "session_id": "s001"},
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(0, 9, 15), "source_ip": "192.168.1.20", "session_id": "s002"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(0, 14, 30), "source_ip": "192.168.1.30", "session_id": "s003"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(0, 22, 30), "source_ip": "192.168.1.40", "session_id": "s004"},
    # Martes 7
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(1, 3, 0), "source_ip": "192.168.1.10", "session_id": "s005"},
    {"account": "adm_deploy", "event_type": "sudo", "timestamp": _ts(1, 10, 0), "source_ip": "192.168.1.20", "session_id": "s006"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(1, 16, 45), "source_ip": "192.168.1.30", "session_id": "s007"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(1, 19, 0), "source_ip": "192.168.1.40", "session_id": "s008"},
    # Miércoles 8
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(2, 1, 30), "source_ip": "192.168.1.10", "session_id": "s009"},
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(2, 8, 0), "source_ip": "192.168.1.20", "session_id": "s010"},
    {"account": "svc_dbadmin", "event_type": "query", "timestamp": _ts(2, 12, 0), "source_ip": "192.168.1.30", "session_id": "s011"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(2, 20, 15), "source_ip": "192.168.1.40", "session_id": "s012"},
    # Jueves 9
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(3, 2, 45), "source_ip": "192.168.1.10", "session_id": "s013"},
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(3, 11, 30), "source_ip": "192.168.1.20", "session_id": "s014"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(3, 15, 0), "source_ip": "192.168.1.30", "session_id": "s015"},
    {"account": "adm_infra", "event_type": "sudo", "timestamp": _ts(3, 21, 0), "source_ip": "192.168.1.40", "session_id": "s016"},
    # Viernes 10
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(4, 3, 15), "source_ip": "192.168.1.10", "session_id": "s017"},
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(4, 9, 45), "source_ip": "192.168.1.20", "session_id": "s018"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(4, 17, 30), "source_ip": "192.168.1.30", "session_id": "s019"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(4, 23, 0), "source_ip": "192.168.1.40", "session_id": "s020"},
    # Sábado 11 (fin de semana)
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(5, 1, 0), "source_ip": "192.168.1.10", "session_id": "s021"},
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(5, 10, 0), "source_ip": "192.168.1.20", "session_id": "s022"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(5, 14, 0), "source_ip": "192.168.1.30", "session_id": "s023"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(5, 22, 30), "source_ip": "192.168.1.40", "session_id": "s024"},
    # Domingo 12 (fin de semana)
    {"account": "svc_backup", "event_type": "login", "timestamp": _ts(6, 2, 30), "source_ip": "192.168.1.10", "session_id": "s025"},
    {"account": "adm_deploy", "event_type": "sudo", "timestamp": _ts(6, 8, 30), "source_ip": "192.168.1.20", "session_id": "s026"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(6, 13, 0), "source_ip": "192.168.1.30", "session_id": "s027"},
    {"account": "adm_infra", "event_type": "login", "timestamp": _ts(6, 21, 45), "source_ip": "192.168.1.40", "session_id": "s028"},
    # Eventos extra para cubrir 30
    {"account": "adm_deploy", "event_type": "login", "timestamp": _ts(0, 3, 0), "source_ip": "192.168.1.20", "session_id": "s029"},
    {"account": "svc_dbadmin", "event_type": "login", "timestamp": _ts(3, 22, 30), "source_ip": "192.168.1.30", "session_id": "s030"},
]

# 6 políticas de ejemplo equivalentes al YAML
MOCK_POLICIES = [
    {"name": "svc_backup_policy", "account": "svc_backup", "group": None, "allowed_window": {"start": "01:00", "end": "05:00"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "timezone": "UTC", "risk_level": "medium"},
    {"name": "adm_deploy_policy", "account": "adm_deploy", "group": None, "allowed_window": {"start": "08:00", "end": "20:00"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "timezone": "UTC", "risk_level": "high"},
    {"name": "svc_dbadmin_policy", "account": "svc_dbadmin", "group": None, "allowed_window": {"start": "06:00", "end": "22:00"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat"], "timezone": "UTC", "risk_level": "high"},
    {"name": "adm_infra_policy", "account": "adm_infra", "group": None, "allowed_window": {"start": "07:00", "end": "21:00"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "timezone": "UTC", "risk_level": "critical"},
    {"name": "group_admins_policy", "account": None, "group": "admins", "allowed_window": {"start": "08:00", "end": "19:00"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri"], "timezone": "UTC", "risk_level": "high"},
    {"name": "group_services_policy", "account": None, "group": "services", "allowed_window": {"start": "00:00", "end": "23:59"}, "allowed_days": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "timezone": "UTC", "risk_level": "low"},
]

@app.get("/api/mock/events")
def get_events():
    """Devuelve la lista de eventos de acceso privilegiado simulados."""
    return MOCK_EVENTS

@app.get("/api/mock/policies")
def get_policies():
    """Devuelve las políticas de ejemplo en formato JSON."""
    return MOCK_POLICIES

if __name__ == '__main__':
    port = int(os.getenv("MOCK_PORT", "8001"))
    uvicorn.run(app, host='0.0.0.0', port=port)
