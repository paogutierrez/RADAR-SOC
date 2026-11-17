"""Modelos de datos compartidos por todos los módulos.

Por qué existe: todos los módulos (normalización, correlación, detección,
alertas) deben "hablar el mismo idioma". Si cada uno usara diccionarios
sueltos, un error tipográfico en una clave rompería la detección en silencio.
Con estas clases el contrato entre módulos es explícito.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Tuple


class Source(str, Enum):
    IDENTITY = "identity"   # Proveedor de identidad (p. ej. Entra ID, Okta)
    ENDPOINT = "endpoint"   # Telemetría del equipo (EDR, Sysmon)
    CLOUD = "cloud"         # Registros de auditoría cloud (CloudTrail, etc.)


# Tipos de evento admitidos por fuente. Todo lo demás se rechaza al normalizar.
ALLOWED_EVENT_TYPES = {
    Source.IDENTITY: {"login_success", "mfa_challenge_passed", "session_use"},
    Source.ENDPOINT: {"credential_store_access", "process_start"},
    Source.CLOUD: {"resource_access"},
}


class Classification(str, Enum):
    """Niveles de certeza. NO son sinónimos.

    ANOMALY          -> algo distinto de lo habitual; puede ser totalmente legítimo.
    SUSPICION        -> varias señales independientes coinciden; requiere revisión.
    STRONG_SUSPICION -> además hay evidencia de endpoint compatible con robo de
                        credenciales/sesión; prioridad alta de investigación.
    CONFIRMED        -> RESERVADO. Solo un analista humano (o una fuente externa
                        concluyente) puede establecerlo. El detector NUNCA lo emite.
    """
    ANOMALY = "anomaly"
    SUSPICION = "suspicion"
    STRONG_SUSPICION = "strong_suspicion"
    CONFIRMED = "confirmed_compromise"


class Severity(str, Enum):
    INFO = "info"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class Event:
    """Evento normalizado. Nunca contiene valores de cookies/tokens/contraseñas."""
    event_id: str
    timestamp: datetime            # siempre con zona horaria (UTC recomendado)
    source: Source
    event_type: str
    user: str
    session_id: Optional[str] = None   # identificador opaco, NO el valor del token
    device_id: Optional[str] = None
    ip: Optional[str] = None
    country: Optional[str] = None
    asn: Optional[int] = None
    user_agent: Optional[str] = None
    process_name: Optional[str] = None
    resource: Optional[str] = None
    resource_sensitivity: Optional[str] = None   # "low" | "medium" | "high"
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Signal:
    """Una señal individual y explicable que aportó al riesgo."""
    code: str
    description: str
    weight: int                    # positivo suma riesgo, negativo es mitigación
    category: str                  # para exigir corroboración entre categorías
    evidence_event_ids: Tuple[str, ...] = ()


@dataclass
class Finding:
    """Resultado interno del detector para una sesión (antes de ser alerta)."""
    rule_id: str
    user: str
    session_id: str                # interno; se pseudonimiza al generar la alerta
    classification: Classification
    severity: Severity
    risk_score: int
    signals: list
    first_seen: datetime
    last_seen: datetime
    origin_event_id: str
    pivot_event_id: str
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_alertable(self) -> bool:
        return self.classification in (
            Classification.SUSPICION, Classification.STRONG_SUSPICION)
