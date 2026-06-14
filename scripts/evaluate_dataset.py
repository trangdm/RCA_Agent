"""Evaluate RCA accuracy on a synthetic dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="")
    parser.add_argument("--per-category", type=int, default=20)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default="")
    args = parser.parse_args()

    if args.input:
        incidents = json.loads(Path(args.input).read_text(encoding="utf-8"))
    else:
        incidents = generate_dataset(per_category=args.per_category, seed=args.seed)

    evaluation = evaluate_incidents(incidents)
    text = json.dumps(evaluation, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
