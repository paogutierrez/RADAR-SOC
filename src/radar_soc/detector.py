"""Identity Threat Detection: RADAR-IDENTITY-001.

Flujo por sesión:
 1. Localizar el evento de ORIGEN (login_success).
 2. Buscar el primer uso posterior desde un contexto DIVERGENTE
    (dispositivo, IP o navegador distintos) -> "pivote".
 3. Construir señales explicables (identidad, red, endpoint, cloud).
 4. Puntuar, clasificar y devolver un Finding.

IMPORTANTE: el detector infiere por contexto. No ve cookies, por lo que
nunca afirma "robo de cookie confirmado".
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from .baseline import Baseline
from .correlation import build_sessions, endpoint_events_for, lookback_start
from .models import Event, Finding, Signal
from .rules import RADAR_IDENTITY_001
from .scoring import STEALER_CODE, classify, compute_score, severity_for

USE_EVENT_TYPES = {"session_use", "resource_access"}


@dataclass
class DetectorConfig:
    endpoint_lookback: timedelta = timedelta(hours=24)
    browser_processes: frozenset = frozenset(
        {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"})
    suspicious_path_classes: frozenset = frozenset({"temp", "user_writable"})


@dataclass
class AnalysisResult:
    findings: list
    skipped_sessions: int      # sesiones sin evento de origen (no comparables)
    uncorrelatable_events: int # eventos sin session_id


def _diverges(origin: Event, ev: Event) -> bool:
    """Compara solo los atributos presentes en AMBOS eventos."""
    for attr in ("device_id", "ip", "user_agent"):
        a, b = getattr(origin, attr), getattr(ev, attr)
        if a and b and a != b:
            return True
    return False


def _first(events: list, attr: str):
    for ev in events:
        value = getattr(ev, attr)
        if value:
            return value
    return None


class SessionReuseDetector:
    def __init__(self, baseline: Optional[Baseline] = None,
                 config: Optional[DetectorConfig] = None):
        self.baseline = baseline or Baseline()
        self.config = config or DetectorConfig()
        self.rule = RADAR_IDENTITY_001

    def analyze(self, events: list) -> AnalysisResult:
        ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
        sessions = build_sessions(ordered)
        findings, skipped = [], 0
        for track in sessions.values():
            if track.origin is None:
                skipped += 1
                continue
            finding = self._analyze_session(track, ordered)
            if finding is not None:
                findings.append(finding)
        uncorrelatable = sum(1 for e in ordered if e.session_id is None
                             and e.source.value != "endpoint")
        return AnalysisResult(findings, skipped, uncorrelatable)

    # ------------------------------------------------------------------
    def _analyze_session(self, track, all_events) -> Optional[Finding]:
        origin = track.origin
        uses = [e for e in track.events
                if e.event_type in USE_EVENT_TYPES and e.timestamp > origin.timestamp]
        divergent = [e for e in uses if _diverges(origin, e)]
        if not divergent:
            return None
        pivot = divergent[0]

        signals: list = []
        signals += self._session_context_signals(track, origin, pivot, divergent)
        signals += self._network_signals(origin, divergent)
        signals += self._impact_signals(divergent)
        signals += self._endpoint_signals(all_events, origin, pivot)
        signals += self._mitigations(origin, divergent, signals)

        if not any(s.weight > 0 for s in signals):
            return None

        score = compute_score(signals)
        classification = classify(signals, score)
        evidence_ids = {origin.event_id, pivot.event_id}
        for s in signals:
            evidence_ids.update(s.evidence_event_ids)
        by_id = {e.event_id: e for e in all_events}
        times = [by_id[i].timestamp for i in evidence_ids if i in by_id]
        return Finding(
            rule_id=self.rule.rule_id, user=origin.user,
            session_id=track.session_id, classification=classification,
            severity=severity_for(classification, score), risk_score=score,
            signals=signals, first_seen=min(times), last_seen=max(times),
            origin_event_id=origin.event_id, pivot_event_id=pivot.event_id)

    # --- Señales ------------------------------------------------------
    def _session_context_signals(self, track, origin, pivot, divergent) -> list:
        out = []
        new_device = _first(divergent, "device_id")
        new_ua = _first(divergent, "user_agent")
        device_changed = bool(new_device and origin.device_id
                              and new_device != origin.device_id)
        ua_changed = bool(new_ua and origin.user_agent and new_ua != origin.user_agent)
        dev_ev = tuple(e.event_id for e in divergent if e.device_id == new_device)[:3]

        if device_changed:
            out.append(Signal(
                "device_mismatch",
                f"La sesión creada en el dispositivo '{origin.device_id}' se usó "
                f"desde '{new_device}'.", 30, "session_context",
                (origin.event_id,) + dev_ev))
            if not self.baseline.is_known_device(origin.user, new_device):
                out.append(Signal(
                    "unknown_device",
                    f"El dispositivo '{new_device}' no está en la línea base de "
                    f"{origin.user}.", 15, "device", dev_ev))
        if ua_changed:
            out.append(Signal(
                "user_agent_change",
                "El navegador/cliente cambió dentro de la misma sesión.",
                10, "session_context", (pivot.event_id,)))
        if device_changed or ua_changed:
            reauth = [e for e in track.events
                      if e.event_type == "mfa_challenge_passed"
                      and origin.timestamp < e.timestamp <= pivot.timestamp
                      and (new_device is None or e.device_id == new_device)]
            if not reauth:
                out.append(Signal(
                    "no_reauth_in_new_context",
                    "No hay autenticación/MFA en el nuevo contexto antes de "
                    "usar la sesión.", 10, "session_context", (pivot.event_id,)))
        return out

    def _network_signals(self, origin, divergent) -> list:
        new_ip = _first(divergent, "ip")
        new_country = _first(divergent, "country")
        new_asn = _first(divergent, "asn")
        if self.baseline.is_corporate_network(new_ip, new_asn):
            return []  # red corporativa: se trata como mitigación
        evidence = tuple(e.event_id for e in divergent if e.ip == new_ip)[:3]
        if origin.country and new_country and origin.country != new_country:
            return [Signal(
                "network_country_change",
                f"La sesión pasó del país {origin.country} a {new_country}.",
                20, "network", evidence)]
        if origin.asn and new_asn and origin.asn != new_asn:
            return [Signal(
                "network_asn_change",
                f"Cambio de proveedor de red (ASN {origin.asn} -> {new_asn}).",
                10, "network", evidence)]
        return []

    def _impact_signals(self, divergent) -> list:
        sensitive = [e for e in divergent if e.resource_sensitivity == "high"]
        if not sensitive:
            return []
        names = ", ".join(sorted({e.resource or "recurso sensible" for e in sensitive}))
        return [Signal(
            "sensitive_resource_access",
            f"Desde el contexto divergente se accedió a recursos sensibles: {names}.",
            15, "impact", tuple(e.event_id for e in sensitive)[:5])]

    def _endpoint_signals(self, all_events, origin, pivot) -> list:
        start = lookback_start(origin.timestamp, pivot.timestamp,
                               self.config.endpoint_lookback)
        evidence = endpoint_events_for(all_events, origin.user, origin.device_id,
                                       start, pivot.timestamp)
        stealer = [e for e in evidence if e.event_type == "credential_store_access"
                   and e.process_name not in self.config.browser_processes]
        suspicious = [e for e in evidence if e.event_type == "process_start"
                      and e.details.get("signed") is False
                      and e.details.get("path_class") in self.config.suspicious_path_classes]
        out = []
        if stealer:
            procs = ", ".join(sorted({e.process_name or "?" for e in stealer}))
            out.append(Signal(
                STEALER_CODE,
                f"En el equipo de origen, un proceso que no es navegador ({procs}) "
                "accedió al almacén de credenciales/cookies del navegador antes del "
                "uso divergente. Es un indicador compatible con infostealer, "
                "no una prueba.", 35, "endpoint", tuple(e.event_id for e in stealer)[:5]))
        if suspicious:
            out.append(Signal(
                "suspicious_process",
                "Proceso sin firma ejecutado desde ruta temporal/escribible por el "
                "usuario en el equipo de origen.", 15, "endpoint",
                tuple(e.event_id for e in suspicious)[:5]))
        return out

    def _mitigations(self, origin, divergent, signals) -> list:
        out = []
        codes = {s.code for s in signals}
        new_device = _first(divergent, "device_id")
        if "device_mismatch" in codes and self.baseline.is_known_device(
                origin.user, new_device):
            out.append(Signal(
                "mitigation_known_device",
                "El dispositivo nuevo es conocido para este usuario.", -10,
                "mitigation"))
        new_ip, new_asn = _first(divergent, "ip"), _first(divergent, "asn")
        if (self.baseline.is_corporate_network(new_ip, new_asn)
                and not self.baseline.is_corporate_network(origin.ip, origin.asn)):
            out.append(Signal(
                "mitigation_corporate_network",
                "El nuevo contexto proviene de red/VPN corporativa.", -10,
                "mitigation"))
        return out
