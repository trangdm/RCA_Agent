"""Evaluation helpers for synthetic incidents with ground truth."""

from __future__ import annotations

from collections import Counter
from typing import Any

from .pipeline import analyze_incident


def evaluate_incidents(incidents: list[dict[str, Any]]) -> dict[str, Any]:
    results = []
    correct = 0
    by_category: dict[str, Counter[str]] = {}

    for incident in incidents:
        assessment = analyze_incident(incident)
        predicted = assessment["root_cause_analysis"]["root_cause"]
        expected = incident.get("ground_truth_root_cause")
        is_correct = predicted == expected
        correct += int(is_correct)
        category = incident.get("category", "unknown")
        by_category.setdefault(category, Counter())
        by_category[category]["total"] += 1
        by_category[category]["correct"] += int(is_correct)
        results.append(
            {
                "incident_id": incident.get("incident_id"),
                "category": category,
                "expected": expected,
                "predicted": predicted,
                "confidence": assessment["root_cause_analysis"]["confidence"],
                "correct": is_correct,
            }
        )

    total = len(incidents)
    accuracy = correct / total if total else 0.0
    return {
        "total": total,
        "correct": correct,
        "accuracy": round(accuracy, 4),
        "accuracy_percent": round(accuracy * 100, 2),
        "by_category": {
            category: {
                "total": counts["total"],
                "correct": counts["correct"],
                "accuracy_percent": round((counts["correct"] / counts["total"]) * 100, 2) if counts["total"] else 0.0,
            }
            for category, counts in sorted(by_category.items())
        },
        "results": results,
    }
