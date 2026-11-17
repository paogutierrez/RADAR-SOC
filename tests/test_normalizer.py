import copy

from radar_soc.normalizer import normalize_events

GOOD = {"event_id": "e1", "timestamp": "2026-11-10T09:00:00Z", "source": "identity",
        "event_type": "login_success", "user": "Alice@Example.test",
        "session_id": "S1", "ip": "203.0.113.10", "asn": 64501}


def test_valid_event_is_normalized():
    res = normalize_events([GOOD])
    assert not res.errors and len(res.events) == 1
    assert res.events[0].user == "alice@example.test"   # usuario en minúsculas
    assert res.events[0].timestamp.tzinfo is not None


def test_bad_events_are_rejected_without_stopping_others():
    cases = [
        {**GOOD, "event_id": "x1", "timestamp": "ayer"},
        {**GOOD, "event_id": "x2", "timestamp": "2026-11-10T09:00:00"},   # sin zona
        {**GOOD, "event_id": "x3", "ip": "999.1.1.1"},
        {**GOOD, "event_id": "x4", "source": "otra"},
        {**GOOD, "event_id": "x5", "event_type": "borrar_todo"},
        {**GOOD, "event_id": "x6", "asn": "64501"},
        {**GOOD, "event_id": "x7", "session_id": None},
        {**GOOD, "event_id": "x8", "resource_sensitivity": "critica"},
        "no soy un objeto",
    ]
    res = normalize_events([GOOD] + cases)
    assert len(res.events) == 1
    assert len(res.errors) == len(cases)


def test_missing_required_field():
    bad = copy.deepcopy(GOOD)
    del bad["user"]
    res = normalize_events([bad])
    assert res.errors and "user" in res.errors[0]["reason"]


def test_duplicate_event_id_rejected():
    res = normalize_events([GOOD, GOOD])
    assert len(res.events) == 1 and len(res.errors) == 1


def test_non_list_input():
    assert normalize_events({"a": 1}).errors


def test_sensitive_keys_are_removed_and_values_not_kept():
    raw = {**GOOD, "session_cookie": "VALOR-SECRETO", "password": "x",
           "details": {"auth_token": "TOKEN-SECRETO", "ok": 1}}
    res = normalize_events([raw])
    assert res.redactions == 3
    assert res.events[0].details == {"ok": 1}
    assert "SECRETO" not in repr(res.events[0])
