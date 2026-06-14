"""End-to-end AIOps RCA pipeline."""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_root_cause
from .correlation import correlate_events
from .recommendations import build_recommendations
from .store import save_assessment
from .telegram import format_telegram_report, send_telegram_report
from .timeline import build_timeline


def _compat_root(rca: dict[str, Any]) -> dict[str, Any]:
    return {
        "root_cause": rca.get("most_likely_root_cause"),
        "confidence": rca.get("confidence"),
        "ranked_hypotheses": [
            {
                "root_cause": item.get("hypothesis"),
                "confidence": item.get("confidence"),
                "evidence": item.get("supporting_evidence", []),
                "missing_data": item.get("missing_data", []),
            }
            for item in rca.get("root_cause_hypotheses", [])
        ],
        "needs_more_evidence": rca.get("status") == "insufficient_data",
        "method": rca.get("method"),
    }


def analyze_incident(
    incident: dict[str, Any],
    send_telegram: bool = False,
    persist: bool = True,
    chat_id: str | int | None = None,
) -> dict[str, Any]:
    """Analyze one incident payload and return the MVP RCA JSON contract."""

    timeline = build_timeline(incident)
    correlation = correlate_events(timeline)
    rca = analyze_root_cause(incident, timeline, correlation=correlation)
    recommendations = build_recommendations(str(rca.get("most_likely_root_cause", "")))

    assessment: dict[str, Any] = {
        "incident_id": incident.get("incident_id", ""),
        "severity": rca.get("severity", (incident.get("alert") or {}).get("severity", "unknown")),
        "summary": rca.get("summary", ""),
        "timeline": timeline,
        "symptoms": rca.get("symptoms", []),
        "impact": rca.get("impact", ""),
        "root_cause_hypotheses": rca.get("root_cause_hypotheses", []),
        "most_likely_root_cause": rca.get("most_likely_root_cause", "Undetermined"),
        "confidence": rca.get("confidence", 0),
        "evidence": rca.get("evidence", []),
        "recommended_actions": recommendations,
        "missing_data": rca.get("missing_data", []),
        "status": rca.get("status", "insufficient_data"),
        "correlation": correlation,
        "category": incident.get("category", "unknown"),
        "ground_truth_root_cause": incident.get("ground_truth_root_cause"),
        "method": rca.get("method"),
    }

    assessment["root_cause_analysis"] = _compat_root(assessment)
    assessment["recommendations"] = recommendations
    assessment["telegram_report"] = format_telegram_report(assessment)

    if persist:
        assessment["store"] = save_assessment(incident, assessment)
    if send_telegram:
        assessment["telegram_delivery"] = send_telegram_report(assessment["telegram_report"], chat_id=chat_id)
    return assessment
