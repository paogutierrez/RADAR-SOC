"""Genera los escenarios SIMULADOS de data/scenarios/.
Todos los datos son ficticios: IPs de rangos de documentación (RFC 5737),
ASN privados/documentación, dominios .test. Ejecutar: python tools/make_scenarios.py
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "data" / "scenarios"
ALICE, BOB = "alice@example.test", "bob@example.test"
CHROME_WIN = "Chrome/130 Windows"


def ev(i, ts, source, etype, user, **kw):
    d = {"event_id": i, "timestamp": f"2026-11-10T{ts}Z", "source": source,
         "event_type": etype, "user": user}
    d.update(kw)
    return d


def login(i, ts, user, sid, dev, ip="203.0.113.10", asn=64501, country="CO", ua=CHROME_WIN):
    return ev(i, ts, "identity", "login_success", user, session_id=sid,
              device_id=dev, ip=ip, asn=asn, country=country, user_agent=ua)


SCENARIOS = {
 "01_legit_ip_change_same_device": dict(
    description="Alice cambia de Wi-Fi a datos móviles con el mismo portátil. Legítimo.",
    expected={"classification": "anomaly", "alert": False,
              "signals_include": ["network_asn_change"], "signals_exclude": ["device_mismatch"]},
    events=[login("e1", "09:00:00", ALICE, "S1", "laptop-alice-01"),
            ev("e2", "11:00:00", "identity", "session_use", ALICE, session_id="S1",
               device_id="laptop-alice-01", ip="203.0.113.77", asn=64502, country="CO", user_agent=CHROME_WIN),
            ev("e3", "11:05:00", "cloud", "resource_access", ALICE, session_id="S1", ip="203.0.113.77",
               asn=64502, country="CO", resource="sharepoint://team-notes", resource_sensitivity="low")]),
 "02_legit_device_switch_with_mfa": dict(
    description="Bob continúa su sesión en su tablet conocida tras pasar MFA. Legítimo.",
    expected={"classification": "anomaly", "alert": False,
              "signals_include": ["device_mismatch"], "signals_exclude": ["no_reauth_in_new_context", "unknown_device"]},
    events=[login("e1", "08:00:00", BOB, "S2", "laptop-bob-01"),
            ev("e2", "08:50:00", "identity", "mfa_challenge_passed", BOB, session_id="S2",
               device_id="tablet-bob-01", ip="203.0.113.90", asn=64501, country="CO", user_agent="Safari/17 iPadOS"),
            ev("e3", "08:52:00", "identity", "session_use", BOB, session_id="S2",
               device_id="tablet-bob-01", ip="203.0.113.90", asn=64501, country="CO", user_agent="Safari/17 iPadOS")]),
 "03_legit_new_device_new_session": dict(
    description="Bob inicia una sesión NUEVA en un dispositivo nuevo con MFA. No hay reutilización.",
    expected={"classification": "none", "alert": False},
    events=[login("e1", "10:00:00", BOB, "S3", "dev-new-bob", ip="203.0.113.120", ua="Firefox/131 Windows"),
            ev("e2", "10:00:20", "identity", "mfa_challenge_passed", BOB, session_id="S3",
               device_id="dev-new-bob", ip="203.0.113.120", asn=64501, country="CO", user_agent="Firefox/131 Windows")]),
 "04_benign_browser_cookie_access_hotspot": dict(
    description="Chrome lee su propio almacén de cookies; cambio a hotspot. Legítimo.",
    expected={"classification": "anomaly", "alert": False, "signals_exclude": ["endpoint_stealer_indicator"]},
    events=[login("e1", "09:00:00", ALICE, "S4", "laptop-alice-01"),
            ev("e2", "09:10:00", "endpoint", "credential_store_access", ALICE, device_id="laptop-alice-01",
               process_name="chrome.exe", details={"target_class": "browser_cookie_store"}),
            ev("e3", "10:00:00", "identity", "session_use", ALICE, session_id="S4", device_id="laptop-alice-01",
               ip="203.0.113.200", asn=64503, country="CO", user_agent=CHROME_WIN)]),
 "05_night_login_unknown_ip_only": dict(
    description="Solo un login nocturno desde IP desconocida. Anomalía aislada: no debe alertar.",
    expected={"classification": "none", "alert": False},
    events=[login("e1", "03:12:00", ALICE, "S5", "dev-unknown-11", ip="192.0.2.15", asn=64510, country="CO")]),
 "06_stealer_indicator_without_reuse": dict(
    description="Proceso raro lee el almacén del navegador pero la sesión no se reutiliza. Sin correlación, sin alerta.",
    expected={"classification": "none", "alert": False},
    events=[login("e1", "09:00:00", ALICE, "S6", "laptop-alice-01"),
            ev("e2", "09:30:00", "endpoint", "credential_store_access", ALICE, device_id="laptop-alice-01",
               process_name="svch0st.exe", details={"target_class": "browser_cookie_store"})]),
 "07_suspicious_reuse_no_endpoint": dict(
    description="Sesión usada desde dispositivo y país nuevos, acceso sensible, sin evidencia de endpoint.",
    expected={"classification": "suspicion", "alert": True,
              "signals_include": ["device_mismatch", "unknown_device", "network_country_change", "sensitive_resource_access"],
              "signals_exclude": ["endpoint_stealer_indicator"]},
    events=[login("e1", "09:00:00", ALICE, "S7", "laptop-alice-01"),
            ev("e2", "09:40:00", "identity", "session_use", ALICE, session_id="S7", device_id="dev-unknown-77",
               ip="192.0.2.50", asn=64510, country="RO", user_agent="Firefox/131 Linux"),
            ev("e3", "09:42:00", "cloud", "resource_access", ALICE, session_id="S7", ip="192.0.2.50", asn=64510,
               country="RO", user_agent="Firefox/131 Linux", resource="s3://finance-payroll", resource_sensitivity="high")]),
 "08_malicious_stealer_session_reuse": dict(
    description="Proceso sin firma lee cookies del navegador; luego la sesión se usa desde otro país y dispositivo.",
    expected={"classification": "strong_suspicion", "alert": True,
              "signals_include": ["endpoint_stealer_indicator", "suspicious_process", "device_mismatch", "sensitive_resource_access"]},
    events=[login("e1", "09:00:00", ALICE, "S8", "laptop-alice-01"),
            ev("e2", "09:05:00", "endpoint", "process_start", ALICE, device_id="laptop-alice-01",
               process_name="updater_svc.exe", details={"signed": False, "path_class": "temp"}),
            ev("e3", "09:06:00", "endpoint", "credential_store_access", ALICE, device_id="laptop-alice-01",
               process_name="updater_svc.exe", details={"target_class": "browser_cookie_store"}),
            ev("e4", "09:31:00", "identity", "session_use", ALICE, session_id="S8", device_id="dev-unknown-77",
               ip="192.0.2.50", asn=64510, country="RO", user_agent="Firefox/131 Linux"),
            ev("e5", "09:33:00", "cloud", "resource_access", ALICE, session_id="S8", ip="192.0.2.50", asn=64510,
               country="RO", user_agent="Firefox/131 Linux", resource="s3://finance-payroll", resource_sensitivity="high")]),
 "09_legit_known_device_via_corporate_vpn": dict(
    description="Alice usa su teléfono conocido por la VPN corporativa sin MFA nuevo. Bajo riesgo.",
    expected={"classification": "anomaly", "alert": False,
              "signals_exclude": ["network_country_change", "network_asn_change"]},
    events=[login("e1", "09:00:00", ALICE, "S9", "laptop-alice-01"),
            ev("e2", "12:00:00", "identity", "session_use", ALICE, session_id="S9", device_id="phone-alice-01",
               ip="198.51.100.20", asn=64500, country="CO", user_agent="Chrome/130 Android")]),
 "10_invalid_and_sensitive_fields": dict(
    description="Entrada con datos inválidos y campos prohibidos; verifica validación y redacción.",
    expected={"classification": "none", "alert": False},
    events=[login("e1", "09:00:00", ALICE, "S10", "laptop-alice-01"),
            {"event_id": "bad1", "timestamp": "no-es-fecha", "source": "identity",
             "event_type": "session_use", "user": ALICE, "session_id": "S10"},
            ev("e3", "09:10:00", "identity", "session_use", ALICE, session_id="S10",
               device_id="laptop-alice-01", ip="no-es-ip"),
            ev("e4", "09:20:00", "identity", "session_use", ALICE, session_id="S10",
               device_id="laptop-alice-01", ip="203.0.113.10", asn=64501, country="CO", user_agent=CHROME_WIN,
               session_cookie="VALOR-SECRETO-NO-REAL", details={"auth_token": "XYZ"})]),
}

if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for name, spec in SCENARIOS.items():
        payload = {"name": name, "description": spec["description"],
                   "expected": spec["expected"], "events": spec["events"]}
        (OUT / f"{name}.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{len(SCENARIOS)} escenarios generados en {OUT}")
