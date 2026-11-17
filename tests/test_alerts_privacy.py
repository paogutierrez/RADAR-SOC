import json

from radar_soc.alerts import alerts_from_findings, pseudonymize_session

from conftest import analyze_raw, load_scenario, scenario_files


def _alert_for(detector, prefix):
    path = next(p for p in scenario_files() if p.name.startswith(prefix))
    _, result = analyze_raw(detector, load_scenario(path)["events"])
    return alerts_from_findings(result.findings, detector.rule)[0]


def test_alert_has_all_required_explainable_fields(detector):
    alert = _alert_for(detector, "08_")
    for key in ("alert_id", "rule_id", "user", "classification", "severity",
                "risk_score", "summary", "signals", "possible_false_positives",
                "investigation_evidence", "recommended_actions", "mitre_attack",
                "limitations", "analyst_verdict"):
        assert key in alert, key
    assert alert["signals"] and all(s["evidence_event_ids"] for s in alert["signals"])
    assert alert["analyst_verdict"] is None
    assert any("T1539" in t for t in alert["mitre_attack"])


def test_alert_language_does_not_claim_confirmed_theft(detector):
    alert = _alert_for(detector, "08_")
    assert alert["classification"] != "confirmed_compromise"
    assert "NO es un compromiso confirmado" in alert["summary"]


def test_raw_session_id_is_not_in_alert(detector):
    alert = _alert_for(detector, "08_")
    text = json.dumps(alert)
    assert "S8" not in alert["session_ref"] and alert["session_ref"].startswith("sess-")
    assert pseudonymize_session("S8") == alert["session_ref"]
    assert '"S8"' not in text


def test_redacted_secret_values_never_reach_output(detector):
    path = next(p for p in scenario_files() if p.name.startswith("10_"))
    norm, result = analyze_raw(detector, load_scenario(path)["events"])
    assert norm.redactions == 2 and len(norm.errors) == 2
    dumped = json.dumps([repr(e) for e in norm.events])
    assert "SECRETO" not in dumped and "XYZ" not in dumped


def test_anomaly_does_not_create_alert(detector):
    path = next(p for p in scenario_files() if p.name.startswith("01_"))
    _, result = analyze_raw(detector, load_scenario(path)["events"])
    assert result.findings and alerts_from_findings(result.findings, detector.rule) == []


def test_false_positive_hints_are_included(detector):
    alert = _alert_for(detector, "07_")
    assert len(alert["possible_false_positives"]) >= 3
