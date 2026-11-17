import fnmatch
from enum import Enum
from pathlib import Path
from typing import List, Optional

import yaml
from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyModel(BaseModel):
    account_pattern: str = Field(..., description="Patrón glob de cuenta (ej. 'admin-*')")
    allowed_days: List[str] = Field(default_factory=lambda: ["Mon", "Tue", "Wed", "Thu", "Fri"])
    allowed_hours_start: int = Field(8, ge=0, le=23)
    allowed_hours_end: int = Field(20, ge=0, le=23)
    timezone: str = "UTC"
    risk_level: RiskLevel = RiskLevel.MEDIUM
    description: str = ""

    @field_validator("allowed_days")
    @classmethod
    def validate_days(cls, v: List[str]) -> List[str]:
        valid = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
        for day in v:
            if day not in valid:
                raise ValueError(f"Día inválido: {day}. Debe ser uno de {valid}")
        return v


def load_policies(path: str) -> List[PolicyModel]:
    """Carga políticas desde un fichero YAML con clave 'policies'."""
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Fichero de políticas no encontrado: {path}")
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict) or "policies" not in data:
        raise ValueError("El YAML debe contener una clave 'policies' con una lista de políticas")
    policies_raw = data["policies"]
    if not isinstance(policies_raw, list):
        raise ValueError("'policies' debe ser una lista")
    return [PolicyModel(**item) for item in policies_raw]


def match_policy(account: str, policies: List[PolicyModel]) -> Optional[PolicyModel]:
    """Devuelve la política más específica para la cuenta.

    Prioriza coincidencia exacta (sin comodines) y luego el patrón glob más
    específico (mayor longitud de patrón). Si no hay coincidencia, retorna None.
    """
    exact_matches = [p for p in policies if p.account_pattern == account]
    if exact_matches:
        return exact_matches[0]

    glob_matches = [p for p in policies if fnmatch.fnmatch(account, p.account_pattern)]
    if not glob_matches:
        return None

    # El patrón más específico es el más largo (menos comodines implícitos)
    return max(glob_matches, key=lambda p: len(p.account_pattern))
