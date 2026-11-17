import sqlite3
import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class AnomalyRecord(BaseModel):
    account: str
    event_type: str
    timestamp_utc: str
    local_dt: str
    deviation_minutes: int
    risk_score: int
    alert_level: str
    risk_factors: List[str]
    policy_description: str


def init_db(db_path: str) -> sqlite3.Connection:
    """Crea la conexión y la tabla 'anomalies' si no existe."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL,
            event_type TEXT NOT NULL,
            timestamp_utc TEXT NOT NULL,
            local_dt TEXT NOT NULL,
            deviation_minutes INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            alert_level TEXT NOT NULL,
            risk_factors TEXT NOT NULL,
            policy_description TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def save_anomaly(conn: sqlite3.Connection, record: AnomalyRecord) -> int:
    """Inserta un registro de anomalía y devuelve el id generado."""
    created_at = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        """
        INSERT INTO anomalies (
            account, event_type, timestamp_utc, local_dt,
            deviation_minutes, risk_score, alert_level, risk_factors,
            policy_description, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record.account,
            record.event_type,
            record.timestamp_utc,
            record.local_dt,
            record.deviation_minutes,
            record.risk_score,
            record.alert_level,
            json.dumps(record.risk_factors),
            record.policy_description,
            created_at,
        ),
    )
    conn.commit()
    return cursor.lastrowid


def get_anomalies(
    conn: sqlite3.Connection, limit: int = 100, alert_level: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Devuelve las anomalías más recientes, opcionalmente filtradas por nivel."""
    query = "SELECT * FROM anomalies"
    params: List[Any] = []
    if alert_level:
        query += " WHERE alert_level = ?"
        params.append(alert_level)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    rows = conn.execute(query, params).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["risk_factors"] = json.loads(item["risk_factors"])
        result.append(item)
    return result


def get_stats(conn: sqlite3.Connection) -> Dict[str, Any]:
    """Calcula estadísticas agregadas de las anomalías almacenadas."""
    total = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]

    by_account_rows = conn.execute(
        "SELECT account, COUNT(*) as cnt FROM anomalies GROUP BY account"
    ).fetchall()
    by_account = {row["account"]: row["cnt"] for row in by_account_rows}

    by_level_rows = conn.execute(
        "SELECT alert_level, COUNT(*) as cnt FROM anomalies GROUP BY alert_level"
    ).fetchall()
    by_level = {row["alert_level"]: row["cnt"] for row in by_level_rows}

    avg_row = conn.execute(
        "SELECT AVG(deviation_minutes) FROM anomalies"
    ).fetchone()
    avg_deviation = avg_row[0] if avg_row[0] is not None else 0.0

    last_row = conn.execute(
        "SELECT MAX(created_at) FROM anomalies"
    ).fetchone()
    last_scan_at = last_row[0] if last_row[0] else None

    return {
        "total_anomalies": total,
        "by_account": by_account,
        "by_level": by_level,
        "avg_deviation_minutes": round(avg_deviation, 2),
        "last_scan_at": last_scan_at,
    }
