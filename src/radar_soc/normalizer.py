"""Event Normalization: valida y limpia eventos JSON crudos.

Qué problema resuelve: cada fuente (identidad, endpoint, cloud) entrega
formatos y calidades distintas. Aquí se convierten a un único `Event`,
se rechazan datos inválidos SIN detener el procesamiento, y se eliminan
campos que nunca deberíamos almacenar (cookies, tokens, contraseñas).

Relación con un ataque real: un analista SOC necesita evidencia de que
"una sesión se usó desde otro sitio", pero jamás necesita el valor de la
cookie. Si un log lo trae, lo descartamos para no crear un nuevo riesgo.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .models import ALLOWED_EVENT_TYPES, Event, Source

# Si una CLAVE contiene alguno de estos fragmentos, el campo se elimina.
FORBIDDEN_KEY_FRAGMENTS = (
    "password", "passwd", "secret", "token", "cookie",
    "authorization", "api_key", "apikey",
)
REQUIRED_FIELDS = ("event_id", "timestamp", "source", "event_type", "user")
VALID_SENSITIVITY = {"low", "medium", "high"}


@dataclass
class NormalizationResult:
    events: list = field(default_factory=list)
    errors: list = field(default_factory=list)   # [{"index": int, "reason": str}]
    redactions: int = 0                          # campos sensibles eliminados


def _is_forbidden(key: str) -> bool:
    k = key.lower()
    return any(fragment in k for fragment in FORBIDDEN_KEY_FRAGMENTS)


def _redact(obj: Any) -> tuple[Any, int]:
    """Elimina recursivamente claves prohibidas. Devuelve (limpio, nº eliminadas).
    Nunca se registra el VALOR eliminado."""
    count = 0
    if isinstance(obj, dict):
        clean = {}
        for key, value in obj.items():
            if _is_forbidden(str(key)):
                count += 1
                continue
            cleaned, n = _redact(value)
            clean[key] = cleaned
            count += n
        return clean, count
    if isinstance(obj, list):
        items = []
        for value in obj:
            cleaned, n = _redact(value)
            items.append(cleaned)
            count += n
        return items, count
    return obj, 0


def _parse_timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp debe ser texto ISO-8601")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"timestamp inválido: {value!r}") from exc
    if ts.tzinfo is None:
        raise ValueError("timestamp sin zona horaria (use 'Z' o '+00:00')")
    return ts


def _optional_str(raw: dict, key: str) -> Optional[str]:
    value = raw.get(key)
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' debe ser texto")
    return value


def normalize_event(raw: Any) -> tuple[Event, int]:
    """Convierte un dict crudo en Event. Lanza ValueError si es inválido."""
    if not isinstance(raw, dict):
        raise ValueError("el evento debe ser un objeto JSON")
    raw, redactions = _redact(raw)

    for name in REQUIRED_FIELDS:
        if not raw.get(name):
            raise ValueError(f"falta el campo obligatorio '{name}'")

    try:
        source = Source(raw["source"])
    except ValueError:
        raise ValueError(f"source desconocida: {raw['source']!r}") from None
    event_type = raw["event_type"]
    if event_type not in ALLOWED_EVENT_TYPES[source]:
        raise ValueError(f"event_type '{event_type}' no válido para {source.value}")

    ip = _optional_str(raw, "ip")
    if ip is not None:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError(f"IP inválida: {ip!r}") from None

    asn = raw.get("asn")
    if asn is not None and (not isinstance(asn, int) or isinstance(asn, bool)):
        raise ValueError("'asn' debe ser entero")

    sensitivity = _optional_str(raw, "resource_sensitivity")
    if sensitivity is not None and sensitivity not in VALID_SENSITIVITY:
        raise ValueError(f"resource_sensitivity inválida: {sensitivity!r}")

    session_id = _optional_str(raw, "session_id")
    device_id = _optional_str(raw, "device_id")
    if source is Source.IDENTITY and session_id is None:
        raise ValueError("los eventos de identidad requieren 'session_id'")
    if source is Source.ENDPOINT and device_id is None:
        raise ValueError("los eventos de endpoint requieren 'device_id'")

    details = raw.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("'details' debe ser un objeto")

    event = Event(
        event_id=str(raw["event_id"]),
        timestamp=_parse_timestamp(raw["timestamp"]),
        source=source,
        event_type=event_type,
        user=str(raw["user"]).lower(),
        session_id=session_id,
        device_id=device_id,
        ip=ip,
        country=(_optional_str(raw, "country") or "").upper() or None,
        asn=asn,
        user_agent=_optional_str(raw, "user_agent"),
        process_name=(_optional_str(raw, "process_name") or "").lower() or None,
        resource=_optional_str(raw, "resource"),
        resource_sensitivity=sensitivity,
        details=details,
    )
    return event, redactions


def normalize_events(raw_events: Any) -> NormalizationResult:
    """Normaliza una lista de eventos. Un evento malo NO detiene al resto."""
    result = NormalizationResult()
    if not isinstance(raw_events, list):
        result.errors.append(
            {"index": -1, "reason": "la entrada debe ser una lista de eventos"})
        return result
    seen_ids: set = set()
    for index, raw in enumerate(raw_events):
        try:
            event, redactions = normalize_event(raw)
            if event.event_id in seen_ids:
                raise ValueError(f"event_id duplicado: {event.event_id}")
            seen_ids.add(event.event_id)
        except ValueError as exc:
            result.errors.append({"index": index, "reason": str(exc)})
            continue
        result.events.append(event)
        result.redactions += redactions
    return result
