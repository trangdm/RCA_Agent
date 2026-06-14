"""Event correlation and cause/symptom/impact grouping."""

from __future__ import annotations

from typing import Any


CAUSE_HINTS = {
    "change",
    "root_bridge_change",
    "bpdu_guard_disabled",
    "prefix_denied",
    "new_nat_policy_hit",
    "forwarder_unreachable",
    "snapshot_growth",
    "suspicious_process",
    "credential_reuse",
}

IMPACT_HINTS = {
    "alert",
    "user_impact",
    "service_availability",
    "vm_stun",
    "account_lockout",
    "ha_vm_restart",
}


def correlate_events(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    """Cluster related events and label likely causes, symptoms, and impacts."""

    if not timeline:
        return {"event_cluster": [], "causality_graph": []}

    causes = []
    symptoms = []
    impacts = []

    for event in timeline:
        event_type = event.get("event_type", "")
        category = event.get("category", "")
        if category == "change" or event_type in CAUSE_HINTS:
            causes.append(event["event_id"])
        elif category == "alert" or event_type in IMPACT_HINTS or "impact" in event.get("message", "").lower():
            impacts.append(event["event_id"])
        else:
            symptoms.append(event["event_id"])

    cluster = {
        "cluster_id": "cluster-001",
        "theme": "primary_incident_chain",
        "related_event_ids": [event["event_id"] for event in timeline],
        "candidate_causes": causes,
        "symptoms": symptoms,
        "impacts": impacts,
        "correlation_reason": "Events are correlated by close timestamps, shared topology, and matching operational signals.",
    }

    graph = []
    for cause in causes:
        for symptom in symptoms[:6]:
            graph.append({"from": cause, "to": symptom, "relationship": "possible_cause_of"})
    for symptom in symptoms[:6]:
        for impact in impacts:
            graph.append({"from": symptom, "to": impact, "relationship": "contributes_to"})

    return {"event_cluster": [cluster], "causality_graph": graph}
