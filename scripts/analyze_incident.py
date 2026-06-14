"""Analyze one incident JSON file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiops_incident_agent.pipeline import analyze_incident


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("incident_file")
    parser.add_argument("--telegram", action="store_true")
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    incident = json.loads(Path(args.incident_file).read_text(encoding="utf-8"))
    assessment = analyze_incident(incident, send_telegram=args.telegram)
    text = json.dumps(assessment, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
