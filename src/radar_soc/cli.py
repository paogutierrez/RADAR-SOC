
"""Interfaz de línea de comandos de RADAR SOC."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .alerts import (
    alerts_from_findings,
    pseudonymize_user,
    render_text,
)
from .baseline import Baseline
from .detector import SessionReuseDetector
from .normalizer import normalize_events


def load_events_file(path) -> list:
    """Acepta una lista JSON o un objeto con la clave 'events'."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"no se pudo leer {path}: {exc}") from exc

    if isinstance(data, dict) and "events" in data:
        return data["events"]
    return data


def run(events_path, baseline_path=None, key=None) -> dict:
    if key is None:
        key = os.environ.get("RADAR_SOC_PSEUDONYM_KEY")

    if not key or len(key) < 32:
        raise ValueError(
            "Falta RADAR_SOC_PSEUDONYM_KEY o tiene menos de 32 caracteres."
        )

    baseline = Baseline.from_file(baseline_path) if baseline_path else Baseline()
    norm = normalize_events(load_events_file(events_path))

    detector = SessionReuseDetector(baseline)
    result = detector.analyze(norm.events)

    alerts = alerts_from_findings(result.findings, detector.rule, key)

    return {
        "stats": {
            "events_valid": len(norm.events),
            "events_rejected": len(norm.errors),
            "fields_redacted": norm.redactions,
            "findings": len(result.findings),
            "alerts": len(alerts),
            "sessions_skipped_no_origin": result.skipped_sessions,
        },
        "errors": norm.errors,
        "observations": [
            {
                "user_ref": pseudonymize_user(f.user, key),
                "classification": f.classification.value,
                "risk_score": f.risk_score,
                "signals": [s.code for s in f.signals],
            }
            for f in result.findings if not f.is_alertable
        ],
        "alerts": alerts,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="RADAR SOC - RADAR-IDENTITY-001")
    parser.add_argument("--events", required=True, help="JSON con eventos")
    parser.add_argument("--baseline", help="JSON de línea base")
    parser.add_argument("--output", help="Guardar el resultado completo en JSON")
    args = parser.parse_args(argv)

    try:
        report = run(args.events, args.baseline)
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    print("Resumen:", json.dumps(report["stats"], ensure_ascii=False))

    for err in report["errors"]:
        print(f"  evento rechazado #{err['index']}: {err['reason']}")

    for obs in report["observations"]:
        print(f"  observación (sin alerta): {obs}")

    for alert in report["alerts"]:
        print(render_text(alert))

    if not report["alerts"]:
        print("Sin alertas.")

    if args.output:
        Path(args.output).write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Resultado guardado en {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
