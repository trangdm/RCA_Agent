"""Synthetic incident generator for research and testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from typing import Any

from .catalog import COMMON_TOPOLOGY, TEMPLATES, IncidentTemplate


TOPOLOGY = COMMON_TOPOLOGY
LOWER_IS_BAD_METRICS = {"route_count", "service_availability"}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _device(role: str) -> str:
    return TOPOLOGY.get(role, role)


def _new_timestamp(start: datetime, offset_minutes: int | float, jitter_seconds: int = 0) -> str:
    return _iso(start + timedelta(minutes=float(offset_minutes), seconds=jitter_seconds))


def _metric_breach(metric: str, value: int | float, threshold: int | float | None, phase: str) -> bool:
    if threshold is None:
        return False
    if phase == "before":
        return False
    if metric in LOWER_IS_BAD_METRICS:
        return value < threshold
    return value >= threshold


def _build_topology(template: IncidentTemplate) -> dict[str, Any]:
    impacted_node = _device(template.topology_role)
    return {
        "firewall": TOPOLOGY["firewall"],
        "core_switch": TOPOLOGY["core_switch"],
        "access_switch": TOPOLOGY["access_switch"],
        "edge_router": TOPOLOGY["edge_router"],
        "dns_server": TOPOLOGY["dns_server"],
        "linux_server": TOPOLOGY["linux_server"],
        "windows_server": TOPOLOGY["windows_server"],
        "vmware_cluster": TOPOLOGY["vmware_cluster"],
        "vmware_datastore": TOPOLOGY["vmware_datastore"],
        "identity_server": TOPOLOGY["identity_server"],
        "wazuh": TOPOLOGY["wazuh"],
        "impacted_node": impacted_node,
        "impacted_service": template.impacted_service,
        "links": [
            {"from": "ARUBA-ACC-03", "to": "JUN-CORE-01", "type": "access-uplink"},
            {"from": "JUN-CORE-01", "to": "FGT-HQ-01", "type": "core-firewall"},
            {"from": "FGT-HQ-01", "to": "ISP-HCM-EDGE", "type": "internet-edge"},
            {"from": "APP-LNX-01", "to": "JUN-CORE-01", "type": "server-access"},
            {"from": "WIN-APP-01", "to": "JUN-CORE-01", "type": "server-access"},
            {"from": "VCENTER-HCM-01", "to": "DS-PRD-01", "type": "storage"},
            {"from": "WAZUH-MGR-01", "to": "IAM-PRD-01", "type": "security-monitoring"},
        ],
    }


def _build_changes(template: IncidentTemplate, start: datetime, rng: random.Random) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for index, change in enumerate(template.change_events, start=1):
        changes.append(
            {
                "change_id": f"CHG-{rng.randint(100000, 999999)}-{index}",
                "time": _new_timestamp(start, change["offset"], rng.randint(0, 20)),
                "device": _device(str(change["device_role"])),
                "action": str(change["action"]),
                "actor": str(change.get("actor", "synthetic-operator")),
                "status": "in_change",
                "source": "change_calendar",
            }
        )
    return sorted(changes, key=lambda item: item["time"])


def _build_logs(template: IncidentTemplate, start: datetime, rng: random.Random) -> list[dict[str, Any]]:
    logs: list[dict[str, Any]] = []
    for event in template.log_events:
        logs.append(
            {
                "timestamp": _new_timestamp(start, event["offset"], rng.randint(0, 35)),
                "source": _device(str(event["source_role"])),
                "event_type": str(event["event_type"]),
                "severity": str(event.get("severity", template.severity)),
                "message": str(event["message"]),
                "role": str(event.get("role", "evidence")),
                "signal": "related",
            }
        )
    for event in template.noise_events:
        logs.append(
            {
                "timestamp": _new_timestamp(start, event["offset"], rng.randint(0, 35)),
                "source": _device(str(event["source_role"])),
                "event_type": str(event["event_type"]),
                "severity": str(event.get("severity", "info")),
                "message": str(event["message"]),
                "role": "noise",
                "signal": "noise",
            }
        )
    return sorted(logs, key=lambda item: item["timestamp"])


def _build_metrics(template: IncidentTemplate, start: datetime, rng: random.Random) -> list[dict[str, Any]]:
    metrics: list[dict[str, Any]] = []
    for point in template.metric_series:
        value = point["value"]
        phase = str(point.get("phase", "during"))
        metric = str(point["metric"])
        threshold = point.get("threshold")
        metrics.append(
            {
                "timestamp": _new_timestamp(start, point["offset"], rng.randint(0, 25)),
                "source": _device(str(point["source_role"])),
                "metric": metric,
                "value": value,
                "unit": str(point.get("unit", "")),
                "threshold": threshold,
                "phase": phase,
                "breach": _metric_breach(metric, value, threshold, phase),
            }
        )
    return sorted(metrics, key=lambda item: item["timestamp"])


def _build_scenario_timeline(incident: dict[str, Any]) -> list[dict[str, str]]:
    timeline: list[dict[str, str]] = []
    for change in incident.get("recent_changes", []):
        timeline.append(
            {
                "time": change["time"],
                "event": change["action"],
                "source": change["device"],
                "type": "change",
            }
        )
    for log in incident.get("logs", []):
        if log.get("signal") == "noise":
            continue
        timeline.append(
            {
                "time": log["timestamp"],
                "event": log["message"],
                "source": log["source"],
                "type": str(log.get("role", "evidence")),
            }
        )
    timeline.append(
        {
            "time": incident["alert"]["timestamp"],
            "event": incident["alert"]["message"],
            "source": incident["alert"]["source"],
            "type": "symptom",
        }
    )
    return sorted(timeline, key=lambda item: item["time"])


def generate_incident(
    incident_id: str,
    template: IncidentTemplate,
    base_time: datetime | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    """Generate one incident payload from a template."""

    rng = random.Random(seed)
    start = base_time or datetime(2026, 6, 14, 3, 0, tzinfo=timezone.utc)
    alert_offset = 6

    changes = _build_changes(template, start, rng)
    logs = _build_logs(template, start, rng)
    metrics = _build_metrics(template, start, rng)
    alert = {
        "timestamp": _new_timestamp(start, alert_offset, rng.randint(0, 20)),
        "severity": template.severity,
        "message": template.alert_message,
        "source": _device(template.topology_role),
    }

    incident = {
        "incident_id": incident_id,
        "scenario_key": template.key,
        "category": template.category,
        "title": template.alert_message,
        "generated_at": _iso(datetime.now(timezone.utc)),
        "ground_truth_root_cause": template.root_cause,
        "alert": alert,
        "logs": logs,
        "metrics": metrics,
        "topology": _build_topology(template),
        "recent_changes": changes,
        "change_history": list(changes),
        "baseline": {
            "metrics": dict(template.baseline),
            "normal_behavior": template.summary,
            "impact_reference": template.impact,
        },
    }
    incident["scenario_timeline"] = _build_scenario_timeline(incident)
    return incident


def generate_required_scenarios(seed: int = 42) -> list[dict[str, Any]]:
    """Generate one incident for each required MVP scenario."""

    rng = random.Random(seed)
    base = datetime(2026, 6, 14, 1, 0, tzinfo=timezone.utc)
    incidents: list[dict[str, Any]] = []
    for index, template in enumerate(TEMPLATES, start=1):
        incidents.append(
            generate_incident(
                incident_id=f"INC-{index:03d}",
                template=template,
                base_time=base + timedelta(minutes=index * 30),
                seed=rng.randint(1, 10_000_000),
            )
        )
    return incidents


def generate_dataset(per_category: int = 20, seed: int = 42) -> list[dict[str, Any]]:
    """Generate a balanced synthetic dataset for evaluation.

    The catalog has uneven category counts by design, so each category cycles
    through its available templates until ``per_category`` incidents are built.
    """

    rng = random.Random(seed)
    by_category: dict[str, list[IncidentTemplate]] = {}
    for template in TEMPLATES:
        by_category.setdefault(template.category, []).append(template)

    base = datetime(2026, 6, 14, 1, 0, tzinfo=timezone.utc)
    dataset: list[dict[str, Any]] = []
    for category, templates in sorted(by_category.items()):
        for index in range(per_category):
            incident_number = len(dataset) + 1
            template = templates[index % len(templates)]
            dataset.append(
                generate_incident(
                    incident_id=f"INC-{incident_number:03d}",
                    template=template,
                    base_time=base + timedelta(minutes=incident_number * 13),
                    seed=rng.randint(1, 10_000_000),
                )
            )

    rng.shuffle(dataset)
    return dataset
