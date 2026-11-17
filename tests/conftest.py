import json
from pathlib import Path

import pytest

from radar_soc.baseline import Baseline
from radar_soc.detector import SessionReuseDetector
from radar_soc.normalizer import normalize_events

ROOT = Path(__file__).resolve().parent.parent
SCENARIO_DIR = ROOT / "data" / "scenarios"
BASELINE_PATH = ROOT / "data" / "baseline.json"


def load_scenario(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def scenario_files():
    return sorted(SCENARIO_DIR.glob("*.json"))


@pytest.fixture
def baseline():
    return Baseline.from_file(BASELINE_PATH)


@pytest.fixture
def detector(baseline):
    return SessionReuseDetector(baseline)


def analyze_raw(detector, raw_events):
    norm = normalize_events(raw_events)
    return norm, detector.analyze(norm.events)
