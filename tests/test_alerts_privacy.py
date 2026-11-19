
import json
import pytest

from radar_soc.alerts import (
    alerts_from_findings,
    pseudonymize_session,
    pseudonymize_user,
)

from conftest import analyze_raw, load_scenario, scenario_files


def _alert_for(detector, prefix, privacy_key):
    path = next(p for p in scenario_files() if p.name.startswith(prefix))
    _, result = analyze_raw(detector, load_scenario(path)["events"])
    return alerts_from_findings(result.findings, detector.rule, privacy_key)[0]


def test_alert_has_all_required_explainable_fields(detector, privacy_key):
    alert = _alert_for(detector, "08_", privacy_key)
    for key in ("alert_id", "rule_id", "user_ref", "session_ref",
                "classification", "severity", "risk_score", "summary",
                "signals", "possible_false_positives", "investigation_evidence",
                "recommended_actions", "mitre_attack", "limitations",
                "analyst_verdict"):
        assert key in alert, key
    assert "user" not in alert
    assert alert["signals"] and all(s["evidence_event_ids"] for s in alert["signals"])
    assert alert["analyst_verdict"] is None
    assert any("T1539" in t for t in alert["mitre_attack"])


def test_alert_language_does_not_claim_confirmed_theft(detector, privacy_key):
    alert = _alert_for(detector, "08_", privacy_key)
    assert alert["classification"] != "confirmed_compromise"
    assert "NO es un compromiso confirmado" in alert["summary"]


def test_raw_session_id_is_not_in_alert(detector, privacy_key):
    alert = _alert_for(detector, "08_", privacy_key)
    text = json.dumps(alert)
    expected_ref = pseudonymize_session("S8", privacy_key)

    assert alert["session_ref"] == expected_ref
    assert alert["session_ref"].startswith("sess-")
    assert '"S8"' not in text


def test_user_is_pseudonymized(detector, privacy_key):
    alert = _alert_for(detector, "08_", privacy_key)

    assert alert["user_ref"].startswith("user-")
    assert alert["user_ref"] == pseudonymize_user(
        "alice@example.test", privacy_key
    )
    assert "alice@example.test" not in json.dumps(alert)


def test_pseudonyms_are_stable_with_same_key(privacy_key):
    assert pseudonymize_user("alice@example.test", privacy_key) == (
        pseudonymize_user("alice@example.test", privacy_key)
    )
    assert pseudonymize_session("S8", privacy_key) == (
        pseudonymize_session("S8", privacy_key)
    )


def test_different_keys_produce_different_pseudonyms():
    key_one = "key-one-with-at-least-32-characters"
    key_two = "key-two-with-at-least-32-characters"

    assert pseudonymize_user("alice@example.test", key_one) != (
        pseudonymize_user("alice@example.test", key_two)
    )


def test_short_key_is_rejected():
    with pytest.raises(ValueError, match="al menos 32"):
        pseudonymize_session("S8", "short")


def test_redacted_secret_values_never_reach_output(detector):
    path = next(p for p in scenario_files() if p.name.startswith("10_"))
    norm, result = analyze_raw(detector, load_scenario(path)["events"])
    assert norm.redactions == 2 and len(norm.errors) == 2
    dumped = json.dumps([repr(e) for e in norm.events])
    assert "SECRETO" not in dumped and "XYZ" not in dumped


def test_anomaly_does_not_create_alert(detector, privacy_key):
    path = next(p for p in scenario_files() if p.name.startswith("01_"))
    _, result = analyze_raw(detector, load_scenario(path)["events"])
    assert result.findings and alerts_from_findings(
        result.findings, detector.rule, privacy_key
    ) == []


def test_false_positive_hints_are_included(detector, privacy_key):
    alert = _alert_for(detector, "07_", privacy_key)
    assert len(alert["possible_false_positives"]) >= 3


def test_false_positive_hints_have_no_duplicates(detector, privacy_key):
    alert = _alert_for(detector, "08_", privacy_key)
    hints = alert["possible_false_positives"]
    assert len(hints) == len(set(hints))
