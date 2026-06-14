"""Root-cause analysis for synthetic AIOps incidents."""

from __future__ import annotations

import re
from typing import Any

from .catalog import TEMPLATES, TEMPLATES_BY_ROOT_CAUSE, IncidentTemplate


def _normalize(value: Any) -> str:
    text = str(value or "").lower()
    text = text.replace("_", " ").replace("-", " ")
    return re.sub(r"\s+", " ", text).strip()


def _flatten(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_flatten(item) for key, item in value.items() if key not in {"ground_truth_root_cause", "scenario_key"})
    if isinstance(value, list):
        return " ".join(_flatten(item) for item in value)
    if isinstance(value, tuple):
        return " ".join(_flatten(item) for item in value)
    return str(value or "")


def _incident_text(incident: dict[str, Any], timeline: list[dict[str, Any]]) -> str:
    scoped = {
        "title": incident.get("title"),
        "category": incident.get("category"),
        "alert": incident.get("alert"),
        "logs": incident.get("logs"),
        "metrics": incident.get("metrics"),
        "topology": incident.get("topology"),
        "recent_changes": incident.get("recent_changes") or incident.get("change_history"),
        "baseline": incident.get("baseline"),
        "timeline": [
            {
                "event": event.get("event"),
                "source": event.get("source"),
                "event_type": event.get("event_type"),
                "type": event.get("type"),
            }
            for event in timeline
            if event.get("signal") != "noise"
        ],
        "intake": incident.get("intake"),
        "investigation_context": incident.get("investigation_context"),
    }
    return _normalize(_flatten(scoped))


def _term_matches(term: str, text: str) -> bool:
    normalized = _normalize(term)
    return bool(normalized) and normalized in text


def _score_template(template: IncidentTemplate, text: str, incident: dict[str, Any]) -> dict[str, Any]:
    matched_terms: list[str] = []
    score = 0
    candidate_terms = [
        template.key,
        template.root_cause,
        template.alert_message,
        template.impacted_service,
        *template.signatures,
        *template.symptoms,
        *(event["event_type"] for event in template.log_events),
        *(point["metric"] for point in template.metric_series),
    ]
    for term in candidate_terms:
        if _term_matches(str(term), text):
            matched_terms.append(str(term))
            score += 10

    for change in incident.get("recent_changes") or incident.get("change_history") or []:
        change_text = _normalize(_flatten(change))
        if any(_term_matches(term, change_text) for term in template.signatures):
            score += 12
            matched_terms.append("recent_change_match")
            break

    if incident.get("category") == template.category:
        score += 3

    return {
        "template": template,
        "score": score,
        "matched_terms": sorted(set(matched_terms)),
    }


def _collect_supporting_evidence(template: IncidentTemplate, timeline: list[dict[str, Any]], limit: int = 8) -> list[str]:
    evidence: list[str] = []
    terms = tuple(template.signatures) + tuple(event["event_type"] for event in template.log_events)
    for event in timeline:
        if event.get("signal") == "noise":
            continue
        event_text = _normalize(" ".join(str(event.get(key, "")) for key in ("event", "event_type", "source", "type")))
        if any(_term_matches(term, event_text) for term in terms):
            evidence.append(f"{event.get('time')} {event.get('source')}: {event.get('event')}")
        if len(evidence) >= limit:
            break
    return evidence


def _collect_symptoms(timeline: list[dict[str, Any]], limit: int = 8) -> list[str]:
    symptoms: list[str] = []
    for event in timeline:
        if event.get("type") == "symptom" and event.get("signal") != "baseline":
            symptoms.append(f"{event.get('source')}: {event.get('event')}")
        if len(symptoms) >= limit:
            break
    return symptoms


def _collect_impact(timeline: list[dict[str, Any]]) -> str:
    impacts = [event for event in timeline if event.get("type") == "impact" and event.get("signal") != "noise"]
    if impacts:
        return "; ".join(f"{event.get('source')}: {event.get('event')}" for event in impacts[:3])
    return "No explicit impact was found in the incident payload."


def _confidence(score: int, second_score: int, evidence_count: int) -> int:
    if score <= 0:
        return 35
    margin = max(0, score - second_score)
    confidence = 45 + min(35, score // 2) + min(15, margin)
    if evidence_count >= 4:
        confidence += 8
    elif evidence_count < 2:
        confidence = min(confidence, 65)
    return min(96, max(35, confidence))


def _hypothesis(
    template: IncidentTemplate,
    confidence: int,
    supporting_evidence: list[str],
    score: int,
) -> dict[str, Any]:
    contradicting: list[str] = []
    if score <= 0:
        contradicting.append("No matching log, metric, topology, or recent-change evidence in the incident payload.")
    elif not supporting_evidence:
        contradicting.append("Matched weak text signals, but no concrete timeline event supports this hypothesis.")

    missing_data = list(template.missing_data)
    if confidence < 70:
        missing_data.insert(0, "Additional correlated log, metric, or change evidence is required before confirming root cause.")

    return {
        "hypothesis": template.root_cause,
        "confidence": confidence,
        "supporting_evidence": supporting_evidence,
        "contradicting_evidence": contradicting,
        "missing_data": missing_data,
        "verification_steps": list(template.verification_steps),
    }


def _first_related_event(timeline: list[dict[str, Any]]) -> dict[str, Any] | None:
    for event in timeline:
        if event.get("signal") not in {"noise", "baseline"}:
            return event
    return timeline[0] if timeline else None


def _summary(
    incident: dict[str, Any],
    timeline: list[dict[str, Any]],
    most_likely: str,
    confidence: int,
    symptoms: list[str],
) -> str:
    first_event = _first_related_event(timeline)
    start_text = "unknown time"
    first_text = "no clear first event"
    if first_event:
        start_text = str(first_event.get("time", "unknown time"))
        first_text = f"{first_event.get('source')}: {first_event.get('event')}"

    alert_message = (incident.get("alert") or {}).get("message") or incident.get("title") or "incident"
    if most_likely == "Undetermined":
        return (
            f"{alert_message}. Timeline starts at {start_text} with {first_text}. "
            "The available evidence is not strong enough to confirm one root cause."
        )

    symptom_text = "; ".join(symptoms[:3]) if symptoms else "no explicit symptom list"
    return (
        f"{alert_message}. Timeline starts at {start_text} with {first_text}. "
        f"Correlated symptoms include {symptom_text}. The most likely root cause is "
        f"{most_likely} with {confidence}% confidence and still needs verification."
    )


def analyze_root_cause(
    incident: dict[str, Any],
    timeline: list[dict[str, Any]],
    correlation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return RCA fields matching the MVP internal JSON contract."""

    text = _incident_text(incident, timeline)
    scored = [_score_template(template, text, incident) for template in TEMPLATES]
    scored.sort(key=lambda item: item["score"], reverse=True)

    hypotheses: list[dict[str, Any]] = []
    for index, item in enumerate(scored[:5]):
        template = item["template"]
        supporting = _collect_supporting_evidence(template, timeline)
        second_score = scored[1]["score"] if index == 0 and len(scored) > 1 else scored[0]["score"]
        if index > 0:
            second_score = scored[0]["score"]
        confidence = _confidence(int(item["score"]), int(second_score), len(supporting))
        hypotheses.append(_hypothesis(template, confidence, supporting, int(item["score"])))

    top = hypotheses[0] if hypotheses else None
    confidence = int(top["confidence"]) if top else 35
    evidence = list(top.get("supporting_evidence", [])) if top else []
    most_likely = str(top["hypothesis"]) if top and confidence >= 70 and evidence else "Undetermined"
    status = "insufficient_data" if confidence < 70 or most_likely == "Undetermined" else "need_verification"
    if incident.get("confirmed_root_cause") and incident.get("confirmed_root_cause") == most_likely:
        status = "confirmed"

    missing_data: list[str] = []
    if top:
        missing_data.extend(top.get("missing_data", []))
    if not evidence:
        missing_data.insert(0, "No concrete timeline evidence supports a confirmed root cause.")
    missing_data = list(dict.fromkeys(missing_data))

    symptoms = _collect_symptoms(timeline)
    impact = _collect_impact(timeline)
    severity = (incident.get("alert") or {}).get("severity", "unknown")

    return {
        "incident_id": incident.get("incident_id", ""),
        "severity": severity,
        "summary": _summary(incident, timeline, most_likely, confidence, symptoms),
        "symptoms": symptoms,
        "impact": impact,
        "root_cause_hypotheses": hypotheses,
        "most_likely_root_cause": most_likely,
        "confidence": confidence,
        "evidence": evidence,
        "missing_data": missing_data,
        "status": status,
        "method": "deterministic_timeline_correlation",
        "correlation": correlation or {},
    }


def template_for_root_cause(root_cause: str) -> IncidentTemplate | None:
    return TEMPLATES_BY_ROOT_CAUSE.get(root_cause)
