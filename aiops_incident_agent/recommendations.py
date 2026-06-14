"""Recommendation generation for detected root causes."""

from __future__ import annotations

from typing import Any

from .catalog import TEMPLATES_BY_ROOT_CAUSE


SAFE_GUARDRAILS = (
    "Do not delete production data.",
    "Do not factory-reset devices.",
    "Do not disable security controls without an approved change window.",
)


def build_recommendations(root_cause: str) -> dict[str, Any]:
    template = TEMPLATES_BY_ROOT_CAUSE.get(root_cause)
    if template:
        return {
            "immediate_actions": list(template.immediate_actions),
            "verification_actions": list(template.verification_actions),
            "long_term_prevention": list(template.long_term_prevention),
            "safety_guardrails": list(SAFE_GUARDRAILS),
        }
    return {
        "immediate_actions": ["Preserve evidence and stabilize affected service", "Escalate to the owning support team"],
        "verification_actions": ["Confirm alert state and user impact", "Review recent changes around the incident window"],
        "long_term_prevention": ["Add monitoring for the confirmed failure mode", "Document the incident runbook"],
        "safety_guardrails": list(SAFE_GUARDRAILS),
    }
