"""Recommendation generation for detected root causes."""

from __future__ import annotations

from typing import Any

from .catalog import TEMPLATES_BY_ROOT_CAUSE


GENERIC_ACTIONS = {
    "immediate_actions": [
        "Preserve evidence and keep the affected service stable.",
        "Confirm alert state, affected scope, and current impact before making changes.",
        "Review recent changes in the suspected time window.",
    ],
    "verification_actions": [
        "Collect additional logs, metrics, and topology evidence around the incident window.",
        "Validate the operator hypothesis against the timeline before mitigation.",
    ],
    "long_term_prevention": [
        "Document the confirmed failure mode in the runbook.",
        "Add monitoring for the correlated signals once root cause is confirmed.",
    ],
}


def build_recommendations(root_cause: str) -> dict[str, Any]:
    template = TEMPLATES_BY_ROOT_CAUSE.get(root_cause)
    if not template:
        return {key: list(value) for key, value in GENERIC_ACTIONS.items()}

    return {
        "immediate_actions": list(template.immediate_actions),
        "verification_actions": list(template.verification_steps),
        "long_term_prevention": list(template.long_term_prevention),
    }
