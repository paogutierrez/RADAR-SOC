
"""Alert Management: convierte Findings en alertas explicables (JSON).

Privacidad:
- Los usuarios y las sesiones se pseudonimizan con HMAC-SHA256.
- La clave secreta se proporciona desde el entorno.
"""
from __future__ import annotations

import hashlib
import hmac

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


def _validate_key(key: str) -> bytes:
    if not isinstance(key, str) or len(key) < 32:
        raise ValueError(
            "La clave de privacidad debe ser una cadena de al menos 32 caracteres."
        )
    return key.encode("utf-8")


def _pseudonymize(value: str, key: str, prefix: str) -> str:
    secret = _validate_key(key)
    digest = hmac.new(
        secret, value.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    return f"{prefix}-{digest[:12]}"


def pseudonymize_session(session_id: str, key: str) -> str:
    return _pseudonymize(session_id, key, "sess")


def pseudonymize_user(user: str, key: str) -> str:
    return _pseudonymize(user, key, "user")


def build_alert(finding: Finding, rule: DetectionRule, key: str) -> dict:
    user_ref = pseudonymize_user(finding.user, key)
    session_ref = pseudonymize_session(finding.session_id, key)

    alert_digest = hmac.new(
        _validate_key(key),
        f"{rule.rule_id}:{user_ref}:{session_ref}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    alert_id = "ALR-" + alert_digest[:10]

    positive = [s for s in finding.signals if s.weight > 0]
    mitig = [s for s in finding.signals if s.weight < 0]

    dynamic_fp = [
        FP_HINTS[s.code] for s in positive if s.code in FP_HINTS
    ]

    summary = (
        f"{STATUS_TEXT[finding.classification]} Referencia '{user_ref}', "
        f"{len(positive)} señales, riesgo {finding.risk_score}/100."
    )

    return {
        "alert_id": alert_id,
        "rule_id": rule.rule_id,
        "rule_name": rule.name,
        "user_ref": user_ref,
        "session_ref": session_ref,
        "classification": finding.classification.value,
        "severity": finding.severity.value,
        "risk_score": finding.risk_score,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "summary": summary,
        "signals": [
            {
                "code": s.code,
                "description": s.description,
                "weight": s.weight,
                "category": s.category,
                "evidence_event_ids": list(s.evidence_event_ids),
            }
            for s in positive
        ],
        "mitigating_factors": [
            {"code": s.code, "description": s.description, "weight": s.weight}
            for s in mitig
        ],
        "possible_false_positives": list(dict.fromkeys(
            dynamic_fp + list(rule.possible_false_positives)
        )),
        "investigation_evidence": list(rule.investigation_evidence),
        "recommended_actions": list(rule.response_recommendations),
        "mitre_attack": list(rule.mitre_attack),
        "limitations": list(rule.limitations),
        "analyst_verdict": None,
    }


def alerts_from_findings(findings: list, rule: DetectionRule, key: str) -> list:
    """Solo las sospechas generan alertas; las anomalías quedan como observaciones."""
    return [
        build_alert(f, rule, key)
        for f in findings
        if f.is_alertable
    ]


def render_text(alert: dict) -> str:
    lines = [
        f"[{alert['severity'].upper()}] {alert['alert_id']} - {alert['rule_name']}",
        f"  Usuario ref.: {alert['user_ref']}   Sesión: {alert['session_ref']}",
        f"  Clasificación: {alert['classification']}   Riesgo: {alert['risk_score']}/100",
        f"  {alert['summary']}",
        "  Señales:",
    ]

    for s in alert["signals"]:
        lines.append(f"    + {s['code']} (+{s['weight']}): {s['description']}")

    for m in alert["mitigating_factors"]:
        lines.append(f"    - {m['code']} ({m['weight']}): {m['description']}")

    lines.append("  Técnicas MITRE: " + "; ".join(alert["mitre_attack"]))
    return "\n".join(lines)
