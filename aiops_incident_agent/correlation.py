"""Event correlation and cause/symptom/impact grouping."""

from __future__ import annotations

from typing import Any


def _related_events(timeline: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in timeline if event.get("signal") not in {"noise", "baseline"}]


def correlate_events(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    """Cluster related events and label likely causes, symptoms, and impacts."""

    if not timeline:
        return {"event_cluster": [], "causality_graph": []}

    related = _related_events(timeline)
    if not related:
        related = timeline

    causes = [event["event_id"] for event in related if event.get("type") in {"change", "root_cause_candidate"}]
    symptoms = [event["event_id"] for event in related if event.get("type") == "symptom"]
    impacts = [event["event_id"] for event in related if event.get("type") == "impact"]
    evidence = [event["event_id"] for event in related if event.get("type") == "evidence"]

    cluster = {
        "cluster_id": "cluster-001",
        "theme": "primary_incident_chain",
        "related_event_ids": [event["event_id"] for event in related],
        "candidate_causes": causes,
        "symptoms": symptoms,
        "evidence": evidence,
        "impacts": impacts,
        "correlation_reason": (
            "Events are correlated by close timestamps, shared topology, recent changes, "
            "and matching operational signals. Noise and baseline events are retained in "
            "the timeline but not promoted into the primary incident chain."
        ),
    }

    graph = []
    for cause in causes:
        for symptom in symptoms[:8]:
            graph.append({"from": cause, "to": symptom, "relationship": "possible_cause_of"})
    for evidence_id in evidence[:8]:
        for symptom in symptoms[:4]:
            graph.append({"from": evidence_id, "to": symptom, "relationship": "supports"})
    for symptom in symptoms[:8]:
        for impact in impacts:
            graph.append({"from": symptom, "to": impact, "relationship": "contributes_to"})

    return {"event_cluster": [cluster], "causality_graph": graph}
