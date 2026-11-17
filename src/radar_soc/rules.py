"""Definición declarativa de la regla RADAR-IDENTITY-001 (según sección 6)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    name: str
    description: str
    objective: str
    data_sources: tuple
    required_fields: tuple
    trigger_conditions: tuple
    time_window: str
    severity_policy: str
    risk_score_policy: str
    mitre_attack: tuple
    possible_false_positives: tuple
    investigation_evidence: tuple
    response_recommendations: tuple
    limitations: tuple


RADAR_IDENTITY_001 = DetectionRule(
    rule_id="RADAR-IDENTITY-001",
    name="Posible reutilización sospechosa de sesión autenticada",
    description=(
        "Una sesión creada en un contexto (dispositivo, red, navegador) se "
        "vuelve a usar desde un contexto distinto sin una nueva autenticación, "
        "posiblemente combinado con indicios de robo de credenciales en el "
        "equipo de origen y acceso a recursos sensibles."),
    objective=(
        "Detectar de forma temprana indicadores compatibles con secuestro de "
        "sesión, sin afirmar robo de cookies salvo evidencia suficiente."),
    data_sources=("identity (login, MFA, uso de sesión)",
                  "endpoint (acceso a almacén de credenciales, procesos)",
                  "cloud (acceso a recursos)"),
    required_fields=("session_id", "user", "timestamp", "device_id", "ip",
                     "country", "asn", "user_agent", "resource_sensitivity"),
    trigger_conditions=(
        "Existe un evento de origen (login_success) para la sesión.",
        "La sesión se usa después desde un contexto distinto (dispositivo, IP o navegador).",
        "Se acumulan >= 40 puntos con señales de >= 2 categorías independientes.",
        "Ninguna señal aislada genera alerta (IP desconocida, hora nocturna, etc.).",
    ),
    time_window=("Vida de la sesión en el lote analizado; evidencia de endpoint "
                 "en las 24 h previas al primer uso divergente (configurable)."),
    severity_policy=("anomaly: info (sin alerta); suspicion: medium/high; "
                     "strong_suspicion: high/critical. 'confirmed' nunca lo "
                     "asigna el detector."),
    risk_score_policy="Suma ponderada de señales menos mitigaciones, acotada a 0-100.",
    mitre_attack=("T1539 Steal Web Session Cookie",
                  "T1550.004 Use Alternate Authentication Material: Web Session Cookie",
                  "T1555.003 Credentials from Web Browsers",
                  "T1078.004 Valid Accounts: Cloud Accounts"),
    possible_false_positives=(
        "Cambio de red legítimo (móvil/Wi-Fi/VPN) con el mismo equipo.",
        "Usuario que continúa su sesión en otro dispositivo propio mediante SSO.",
        "Proxy, VPN personal o CGNAT que cambian IP/país aparente.",
        "Navegador actualizado que cambia el user-agent.",
        "Empleado nuevo o dispositivo recién enrolado ausente de la línea base.",
        "Software legítimo (backup, antivirus) que lee almacenes del navegador.",
    ),
    investigation_evidence=(
        "Registros de inicio de sesión y MFA de la sesión (origen y nuevo contexto).",
        "Inventario/estado de gestión del dispositivo nuevo (¿existe en MDM?).",
        "Telemetría EDR del equipo de origen: árbol de procesos, firma, ruta, hash.",
        "Historial de acciones cloud posteriores al cambio de contexto.",
        "Confirmación directa con el usuario por un canal independiente.",
        "Reputación de la IP/ASN nuevos (solo con fuentes autorizadas).",
    ),
    response_recommendations=(
        "Verificar con el usuario por un canal alternativo antes de actuar.",
        "Si se confirma sospecha: revocar la sesión y forzar reautenticación "
        "con MFA (acción manual, con autorización).",
        "Aislar el equipo de origen solo si hay evidencia de malware y con aprobación.",
        "Revisar acciones sensibles realizadas desde la sesión sospechosa.",
        "No bloquear cuentas automáticamente desde este detector.",
    ),
    limitations=(
        "No ve el valor de cookies/tokens: infiere por contexto, no demuestra robo.",
        "Sin geolocalización precisa ni 'viaje imposible' por distancia.",
        "Depende de que las fuentes incluyan session_id correlacionable.",
        "Pesos y umbrales son heurísticos, no calibrados con datos reales.",
        "No usa Machine Learning: no se ha entrenado ni evaluado ningún modelo.",
    ),
)
