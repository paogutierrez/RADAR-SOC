import json

from radar_soc.cli import main, run

from conftest import BASELINE_PATH, SCENARIO_DIR


def test_run_malicious_scenario():
    report = run(SCENARIO_DIR / "08_malicious_stealer_session_reuse.json", BASELINE_PATH)
    assert report["stats"]["alerts"] == 1
    assert report["alerts"][0]["classification"] == "strong_suspicion"


def test_run_legit_scenario_has_no_alerts():
    report = run(SCENARIO_DIR / "01_legit_ip_change_same_device.json", BASELINE_PATH)
    assert report["stats"]["alerts"] == 0 and len(report["observations"]) == 1


def test_main_writes_output_file(tmp_path, capsys):
    out = tmp_path / "alerts.json"
    code = main(["--events", str(SCENARIO_DIR / "07_suspicious_reuse_no_endpoint.json"),
                 "--baseline", str(BASELINE_PATH), "--output", str(out)])
    assert code == 0
    assert json.loads(out.read_text(encoding="utf-8"))["stats"]["alerts"] == 1
    assert "suspicion" in capsys.readouterr().out


def test_main_missing_file_returns_error(capsys):
    assert main(["--events", "no_existe.json"]) == 2
    assert "ERROR" in capsys.readouterr().err


def test_main_invalid_json(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{no es json", encoding="utf-8")
    assert main(["--events", str(bad)]) == 2
