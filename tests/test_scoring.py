from radar_soc.models import Classification, Severity, Signal
from radar_soc.scoring import classify, compute_score, severity_for


def sig(code, w, cat):
    return Signal(code, code, w, cat)


def test_score_is_clamped():
    assert compute_score([sig("a", 90, "x"), sig("b", 90, "y")]) == 100
    assert compute_score([sig("a", -50, "mitigation")]) == 0


def test_single_category_never_becomes_suspicion():
    signals = [sig("a", 30, "session_context"), sig("b", 30, "session_context")]
    assert classify(signals, compute_score(signals)) is Classification.ANOMALY


def test_two_categories_and_threshold_gives_suspicion():
    signals = [sig("a", 30, "session_context"), sig("b", 20, "network")]
    assert classify(signals, 50) is Classification.SUSPICION


def test_below_threshold_is_anomaly():
    signals = [sig("a", 20, "network"), sig("b", 10, "session_context")]
    assert classify(signals, 30) is Classification.ANOMALY


def test_stealer_with_context_is_strong():
    signals = [sig("endpoint_stealer_indicator", 35, "endpoint"),
               sig("device_mismatch", 30, "session_context")]
    assert classify(signals, 65) is Classification.STRONG_SUSPICION


def test_stealer_alone_is_not_strong():
    signals = [sig("endpoint_stealer_indicator", 35, "endpoint")]
    assert classify(signals, 35) is Classification.ANOMALY


def test_classifier_never_returns_confirmed():
    signals = [sig("endpoint_stealer_indicator", 100, "endpoint"),
               sig("device_mismatch", 100, "session_context"),
               sig("n", 100, "network")]
    assert classify(signals, 100) is not Classification.CONFIRMED


def test_severity_mapping():
    assert severity_for(Classification.ANOMALY, 30) is Severity.INFO
    assert severity_for(Classification.SUSPICION, 50) is Severity.MEDIUM
    assert severity_for(Classification.SUSPICION, 100) is Severity.HIGH   # sin endpoint no es crítica
    assert severity_for(Classification.STRONG_SUSPICION, 65) is Severity.HIGH
    assert severity_for(Classification.STRONG_SUSPICION, 90) is Severity.CRITICAL
