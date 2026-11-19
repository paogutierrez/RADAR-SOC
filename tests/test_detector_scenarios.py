import pytest

from radar_soc.alerts import alerts_from_findings
from radar_soc.models import Classification

from conftest import analyze_raw, load_scenario, scenario_files


def _ids(path):
    return path.stem


@pytest.mark.parametrize("path", scenario_files(), ids=_ids)
def test_scenario_matches_expectation(path, detector, privacy_key):
    scenario = load_scenario(path)
    expected = scenario["expected"]
    _, result = analyze_raw(detector, scenario["events"])
    alerts = alerts_from_findings(result.findings, detector.rule, privacy_key
)

    assert bool(alerts) == expected["alert"], scenario["description"]
    if expected["classification"] == "none":
        assert result.findings == []
        return
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.classification.value == expected["classification"]
    codes = {s.code for s in finding.signals}
    for code in expected.get("signals_include", []):
        assert code in codes, f"falta señal {code}: {codes}"
    for code in expected.get("signals_exclude", []):
        assert code not in codes, f"señal inesperada {code}"


def test_detector_never_emits_confirmed_in_any_scenario(detector):
    for path in scenario_files():
        _, result = analyze_raw(detector, load_scenario(path)["events"])
        assert all(f.classification is not Classification.CONFIRMED
                   for f in result.findings)


def test_endpoint_evidence_before_login_is_ignored(detector):
    """La cookie no existía antes del login: evidencia previa no cuenta."""
    sc = load_scenario(next(p for p in scenario_files() if "08_" in p.name))
    events = sc["events"]
    for e in events:
        if e["source"] == "endpoint":
            e["timestamp"] = "2026-11-10T08:00:00Z"   # antes del login (09:00)
    _, result = analyze_raw(detector, events)
    codes = {s.code for f in result.findings for s in f.signals}
    assert "endpoint_stealer_indicator" not in codes


def test_endpoint_evidence_from_other_device_is_ignored(detector):
    sc = load_scenario(next(p for p in scenario_files() if "08_" in p.name))
    for e in sc["events"]:
        if e["source"] == "endpoint":
            e["device_id"] = "laptop-de-otra-persona"
    _, result = analyze_raw(detector, sc["events"])
    codes = {s.code for f in result.findings for s in f.signals}
    assert "endpoint_stealer_indicator" not in codes


def test_session_without_origin_is_skipped_not_alerted(detector):
    sc = load_scenario(next(p for p in scenario_files() if "07_" in p.name))
    events = [e for e in sc["events"] if e["event_type"] != "login_success"]
    _, result = analyze_raw(detector, events)
    assert result.findings == [] and result.skipped_sessions == 1


def test_unknown_user_without_baseline_still_needs_corroboration(detector):
    """Un usuario fuera de la línea base solo sube riesgo si hay más señales."""
    events = [
        {"event_id": "a", "timestamp": "2026-11-10T09:00:00Z", "source": "identity",
         "event_type": "login_success", "user": "nuevo@example.test", "session_id": "Z",
         "device_id": "d1", "ip": "203.0.113.5", "asn": 64501, "country": "CO",
         "user_agent": "Chrome/130 Windows"},
        {"event_id": "b", "timestamp": "2026-11-10T09:30:00Z", "source": "identity",
         "event_type": "session_use", "user": "nuevo@example.test", "session_id": "Z",
         "device_id": "d1", "ip": "203.0.113.5", "asn": 64501, "country": "CO",
         "user_agent": "Chrome/130 Windows"}]
    _, result = analyze_raw(detector, events)
    assert result.findings == []   # nada cambió: no hay divergencia
