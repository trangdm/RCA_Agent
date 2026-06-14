"""End-to-end AIOps incident investigation pipeline."""

from __future__ import annotations

from typing import Any

from .analyzer import analyze_root_cause
from .correlation import correlate_events
from .recommendations import build_recommendations
from .telegram import format_telegram_report, send_telegram_report
from .timeline import build_timeline


def analyze_incident(incident: dict[str, Any], send_telegram: bool = False) -> dict[str, Any]:
    """Analyze one incident payload and return a complete assessment."""

    timeline = build_timeline(incident)
    correlation = correlate_events(timeline)
    root_cause_analysis = analyze_root_cause(incident, timeline)
    recommendations = build_recommendations(root_cause_analysis.get("root_cause", ""))

    assessment = {
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "category": incident.get("category"),
        "severity": (incident.get("alert") or {}).get("severity", "unknown"),
        "alert_message": (incident.get("alert") or {}).get("message", ""),
        "alert_source": (incident.get("alert") or {}).get("source", "unknown"),
        "timeline": timeline,
        "correlation": correlation,
        "root_cause_analysis": root_cause_analysis,
        "recommendations": recommendations,
        "status": "Need verification",
    }
    report = format_telegram_report(assessment)
    assessment["telegram_report"] = report
    if send_telegram:
        assessment["telegram_delivery"] = send_telegram_report(report)
    return assessment
