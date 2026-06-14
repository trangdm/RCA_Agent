"""Generate synthetic AIOps incidents."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiops_incident_agent.generator import generate_dataset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--per-category", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="data/generated/incidents.json")
    args = parser.parse_args()

    incidents = generate_dataset(per_category=args.per_category, seed=args.seed)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(incidents, indent=2), encoding="utf-8")
    if incidents:
        Path("incident.json").write_text(json.dumps(incidents[0], indent=2), encoding="utf-8")
    print(f"Generated {len(incidents)} incidents at {output}")
    print("Wrote first generated incident to incident.json")


if __name__ == "__main__":
    main()
