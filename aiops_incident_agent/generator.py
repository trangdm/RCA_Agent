"""Synthetic incident generator for research and testing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from typing import Any

from .catalog import TEMPLATES, IncidentTemplate


TOPOLOGY = {
    "firewall": "FGT-HQ-01",
    "core_switch": "JUN-CORE-01",
    "access_switch": "ARUBA-ACC-03",
    "edge_router": "RTR-HQ-01",
    "dns_server": "DNS-HQ-01",
    "internet_edge": "ISP-HCM-EDGE",
    "app_server": "APP-PRD-01",
    "vmware_datastore": "DS-PRD-01",
    "vmware_host": "ESX-HCM-07",
    "identity_server": "IAM-PRD-01",
    "endpoint": "WIN-OPS-042",
    "server_subnet": "SRV-VLAN-120",
    "switch": "JUN-CORE-01",
    "router": "RTR-HQ-01",
    "server": "APP-PRD-01",
    "dns": "DNS-HQ-01",
    "wan": "ISP-HCM-EDGE",
    "security": "SEC-MON-01",
    "vmware": "VCENTER-HCM-01",
    "camera": "CAM-01",
    "nvr": "NVR-HQ-01",
}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _device(role: str) -> str:
    return TOPOLOGY.get(role, role.upper())


def _jitter(value: int, rng: random.Random, ratio: float = 0.08) -> int:
    delta = max(1, int(abs(value) * ratio))
    return max(0, value + rng.randint(-delta, delta))


def _build_topology(template: IncidentTemplate) -> dict[str, Any]:
    impacted = _device(template.topology_role)
    return {
        "firewall": TOPOLOGY["firewall"],
        "core_switch": TOPOLOGY["core_switch"],
        "access_switch": TOPOLOGY["access_switch"],
        "edge_router": TOPOLOGY["edge_router"],
        "dns_server": TOPOLOGY["dns_server"],
        "app_server": TOPOLOGY["app_server"],
        "camera": TOPOLOGY["camera"],
        "nvr": TOPOLOGY["nvr"],
        "vmware_cluster": "VSPHERE-CLUSTER-01",
        "impacted_node": impacted,
        "impacted_service": template.impacted_service,
        "links": [
            {"from": "CAM-01", "to": "ARUBA-ACC-03", "type": "camera-access"},
            {"from": "NVR-HQ-01", "to": "JUN-CORE-01", "type": "video-recording"},
            {"from": "ARUBA-ACC-03", "to": "JUN-CORE-01", "type": "uplink"},
            {"from": "JUN-CORE-01", "to": "FGT-HQ-01", "type": "core-to-firewall"},
            {"from": "FGT-HQ-01", "to": "ISP-HCM-EDGE", "type": "internet"},
            {"from": "APP-PRD-01", "to": "JUN-CORE-01", "type": "server-access"},
        ],
    }


def generate_incident(
    incident_id: str,
    template: IncidentTemplate,
    base_time: datetime | None = None,
    seed: int | None = None,
) -> dict[str, Any]:
    """Generate one incident payload from a template."""

    rng = random.Random(seed)
    start = base_time or datetime(2026, 6, 14, 3, 0, tzinfo=timezone.utc)
    change_time = start
    first_signal = start + timedelta(minutes=4 + rng.randint(0, 2))
    alert_time = first_signal + timedelta(minutes=4 + rng.randint(0, 2))
    impact_time = alert_time + timedelta(minutes=2 + rng.randint(0, 2))

    source_device = _device(template.topology_role)
    change_device = _device(template.change_device_role)

    logs = []
    for index, event_type in enumerate(template.log_events):
        ts = first_signal + timedelta(minutes=index, seconds=rng.randint(0, 45))
        logs.append(
            {
                "timestamp": _iso(ts),
                "source": source_device,
                "event_type": event_type,
                "severity": template.severity if index >= len(template.log_events) - 2 else "warning",
                "message": f"{event_type.replace('_', ' ')} observed on {source_device}",
            }
        )

    metrics = []
    for index, (source_role, metric, value, threshold, unit) in enumerate(template.metric_points):
        observed = _jitter(value, rng)
        metrics.append(
            {
                "timestamp": _iso(alert_time + timedelta(seconds=index * 30)),
                "source": _device(source_role),
                "metric": metric,
                "value": observed,
                "unit": unit,
                "threshold": threshold,
                "breach": observed >= threshold if threshold else observed > 0,
            }
        )

    alert = {
        "timestamp": _iso(alert_time),
        "severity": template.severity,
        "message": template.alert_message,
        "source": source_device,
    }

    change_history = [
        {
            "time": _iso(change_time),
            "device": change_device,
            "action": template.change_action,
            "actor": "synthetic-operator",
        }
    ]

    logs.append(
        {
            "timestamp": _iso(impact_time),
            "source": template.impacted_service,
            "event_type": "user_impact",
            "severity": template.severity,
            "message": f"Users report impact on {template.impacted_service}",
        }
    )

    return {
        "incident_id": incident_id,
        "category": template.category,
        "title": template.alert_message,
        "generated_at": _iso(datetime.now(timezone.utc)),
        "ground_truth_root_cause": template.root_cause,
        "alert": alert,
        "metrics": metrics,
        "logs": sorted(logs, key=lambda item: item["timestamp"]),
        "topology": _build_topology(template),
        "change_history": change_history,
    }


def generate_dataset(per_category: int = 20, seed: int = 42) -> list[dict[str, Any]]:
    """Generate a balanced dataset with incidents per category."""

    rng = random.Random(seed)
    dataset: list[dict[str, Any]] = []
    counters = {"network": 0, "system": 0, "security": 0}
    by_category: dict[str, list[IncidentTemplate]] = {}
    for template in TEMPLATES:
        by_category.setdefault(template.category, []).append(template)

    base = datetime(2026, 6, 14, 1, 0, tzinfo=timezone.utc)
    for category, templates in sorted(by_category.items()):
        for index in range(per_category):
            template = templates[index % len(templates)]
            counters[category] += 1
            incident_number = len(dataset) + 1
            incident = generate_incident(
                incident_id=f"INC-{incident_number:03d}",
                template=template,
                base_time=base + timedelta(minutes=incident_number * 13),
                seed=rng.randint(1, 10_000_000),
            )
            dataset.append(incident)

    rng.shuffle(dataset)
    return dataset
