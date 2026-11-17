"""Event Correlation: une eventos de identidad, endpoint y cloud.

Qué problema resuelve: una alerta útil rara vez sale de UN log. Aquí se
agrupan los eventos por sesión (identidad + cloud) y se buscan evidencias
del endpoint de origen en una ventana de tiempo.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from .models import Event, Source


@dataclass
class SessionTrack:
    session_id: str
    origin: Optional[Event] = None          # primer login_success de la sesión
    events: list = field(default_factory=list)


def build_sessions(events: list) -> dict:
    """Agrupa por session_id. `events` debe estar ordenado por tiempo."""
    sessions: dict = {}
    for ev in events:
        if ev.session_id is None:
            continue
        track = sessions.setdefault(ev.session_id, SessionTrack(ev.session_id))
        track.events.append(ev)
        if ev.event_type == "login_success" and track.origin is None:
            track.origin = ev
    return sessions


def endpoint_events_for(events: list, user: str, device_id: Optional[str],
                        start: datetime, end: datetime) -> list:
    """Eventos de endpoint del mismo usuario y dispositivo dentro de [start, end]."""
    if device_id is None:
        return []
    return [e for e in events
            if e.source is Source.ENDPOINT and e.user == user
            and e.device_id == device_id and start <= e.timestamp <= end]


def lookback_start(origin_ts: datetime, pivot_ts: datetime,
                   lookback: timedelta) -> datetime:
    """La evidencia debe ser posterior al login (la cookie no existía antes)
    y estar dentro de la ventana de búsqueda."""
    return max(origin_ts, pivot_ts - lookback)
