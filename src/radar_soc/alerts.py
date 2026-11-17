"""Alert Management: convierte Findings en alertas explicables (JSON).

Privacidad: el session_id real nunca sale en la alerta; se reemplaza por una
referencia pseudonimizada (hash). Así el analista puede correlacionar sin
exponer identificadores de sesión.
"""
from __future__ import annotations

import hashlib
from typing import Optional

from .models import Classification, Finding
from .rules import DetectionRule

STATUS_TEXT = {
    Classification.ANOMALY: "Anomalía: comportamiento inusual, sin corroboración suficiente.",
    Classification.SUSPICION: "Sospecha: varias señales independientes coinciden. "
                              "NO es un compromiso confirmado.",
    Classification.STRONG_SUSPICION: "Sospecha fuerte: hay además evidencia de endpoint "
                                     "compatible con robo de credenciales. Requiere validación "
                                     "humana; NO es un compromiso confirmado.",
}

FP_HINTS = {
    "network_country_change": "Podría ser VPN personal, proxy o viaje real del usuario.",
    "network_asn_change": "Cambio normal entre Wi-Fi y datos móviles.",
    "user_agent_change": "Actualización del navegador.",
    "device_mismatch": "Continuidad legítima de sesión entre dispositivos propios (SSO).",
    "unknown_device": "Dispositivo nuevo aún no registrado en la línea base.",
    "endpoint_stealer_indicator": "Software legítimo (backup, EDR, antivirus) que lea "
                                  "almacenes del navegador; verificar firma y hash.",
    "suspicious_process": "Instaladores o herramientas internas sin firma.",
    "sensitive_resource_access": "Acceso legítimo del usuario a un recurso que sí usa.",
}


def pseudonymize_session(session_id: str, salt: str = "radar-soc") -> str:
    digest = hashlib.sha256(f"{salt}:{session_id}".encode()).hexdigest()
    return f"sess-{digest[:12]}"


def build_alert(finding: Finding, rule: DetectionRule, salt: str = "radar-soc") -> dict:
    session_ref = pseudonymize_session(finding.session_id, salt)
    alert_id = "ALR-" + hashlib.sha256(
        f"{rule.rule_id}:{finding.user}:{session_ref}".encode()).hexdigest()[:10]
    positive = [s for s in finding.signals if s.weight > 0]
    mitig = [s for s in finding.signals if s.weight < 0]
    dynamic_fp = [FP_HINTS[s.code] for s in positive if s.code in FP_HINTS]
    summary = (
        f"{STATUS_TEXT[finding.classification]} Usuario '{finding.user}', "
        f"{len(positive)} señales, riesgo {finding.risk_score}/100.")
    return {
        "alert_id": alert_id,
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "user": finding.user,
        "session_ref": session_ref,
        "classification": finding.classification.value,
        "severity": finding.severity.value,
        "risk_score": finding.risk_score,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "summary": summary,
        "signals": [
            {"code": s.code, "description": s.description, "weight": s.weight,
             "category": s.category, "evidence_event_ids": list(s.evidence_event_ids)}
            for s in positive],
        "mitigating_factors": [
            {"code": s.code, "description": s.description, "weight": s.weight}
            for s in mitig],
        "possible_false_positives": dynamic_fp + list(rule.possible_false_positives),
        "investigation_evidence": list(rule.investigation_evidence),
        "recommended_actions": list(rule.response_recommendations),
        "mitre_attack": list(rule.mitre_attack),
        "limitations": list(rule.limitations),
        "analyst_verdict": None,   # solo un analista puede marcar 'confirmed_compromise'
    }


def alerts_from_findings(findings: list, rule: DetectionRule,
                         salt: str = "radar-soc") -> list:
    """Solo SUSPICION y STRONG_SUSPICION generan alerta; ANOMALY queda como
    observación (no alerta) para evitar fatiga de alertas."""
    return [build_alert(f, rule, salt) for f in findings if f.is_alertable]


def render_text(alert: dict) -> str:
    lines = [
        f"[{alert['severity'].upper()}] {alert['alert_id']} - {alert['rule_name']}",
        f"  Usuario: {alert['user']}   Sesión: {alert['session_ref']}",
        f"  Clasificación: {alert['classification']}   Riesgo: {alert['risk_score']}/100",
        f"  {alert['summary']}", "  Señales:"]
    for s in alert["signals"]:
        lines.append(f"    + {s['code']} (+{s['weight']}): {s['description']}")
    for m in alert["mitigating_factors"]:
        lines.append(f"    - {m['code']} ({m['weight']}): {m['description']}")
    lines.append("  Técnicas MITRE: " + "; ".join(alert["mitre_attack"]))
    return "\n".join(lines)
