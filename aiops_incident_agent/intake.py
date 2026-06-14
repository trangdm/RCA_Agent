"""Normalize user-reported incidents into the synthetic incident contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
import re
from typing import Any
import unicodedata

from .catalog import TEMPLATES, IncidentTemplate
from .generator import TOPOLOGY, generate_incident


ROOT_CAUSE_ALIASES = {
    "Broadcast Loop on Aruba switch": (
        "broadcast loop",
        "broadcast storm",
        "loop mang",
        "vong lap",
        "stp topology",
        "mac flapping vlan",
        "aruba loop",
    ),
    "MAC flapping on core switch": (
        "mac flapping",
        "mac flap",
        "duplicate mac",
        "mac move",
        "core switch mac",
    ),
    "Fortigate session spike causing high CPU": (
        "fortigate cpu",
        "firewall cpu",
        "session spike",
        "session table",
        "session full",
        "nat policy",
        "internet slow firewall",
    ),
    "DNS server timeout": (
        "dns timeout",
        "dns cham",
        "khong phan giai",
        "resolve fail",
        "servfail",
        "forwarder",
    ),
    "Linux server disk full": (
        "disk full",
        "day disk",
        "o dia day",
        "no space",
        "enospc",
        "linux disk",
    ),
    "Windows service crash": (
        "windows service crash",
        "service crash",
        "service down",
        "db down",
        "db-01",
        "db 01",
        "database down",
        "mat ket noi server",
        "server down",
        "server unreachable",
    ),
    "VMware datastore full": (
        "vmware datastore",
        "datastore full",
        "snapshot growth",
        "vm stun",
        "ds full",
    ),
    "Interface flapping": (
        "interface flapping",
        "port flap",
        "port flapping",
        "link down up",
        "link up down",
        "ge-0/0/1",
        "ge 0/0/1",
        "camera down",
        "camera 01 down",
        "camera mat ket noi",
        "switch port down",
    ),
    "Routing issue": (
        "routing",
        "route withdrawal",
        "bgp",
        "ospf",
        "mat route",
        "route mat",
        "prefix filter",
    ),
    "Brute force attack detected by Wazuh": (
        "brute force",
        "wazuh",
        "failed login",
        "login failed",
        "account lockout",
        "vpn auth failure",
        "dang nhap that bai",
    ),
}


SEVERITY_TERMS = {
    "critical": ("critical", "crit", "nghiem trong", "outage", "mat dich vu", "khong truy cap"),
    "major": ("major", "high", "cao", "anh huong", "impact"),
    "warning": ("warning", "medium", "canh bao", "degraded"),
    "info": ("info", "low", "minor", "thap"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _new_incident_id(prefix: str = "INC-USER") -> str:
    timestamp = _now().strftime("%Y%m%d%H%M%S")
    suffix = random.SystemRandom().randint(100, 999)
    return f"{prefix}-{timestamp}-{suffix}"


def normalize_text(value: Any) -> str:
    text = str(value or "").lower()
    text = unicodedata.normalize("NFD", text)
    text = "".join(char for char in text if unicodedata.category(char) != "Mn")
    text = text.replace("đ", "d").replace("_", " ").replace("-", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _score_template(template: IncidentTemplate, text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    terms = [
        template.key,
        template.root_cause,
        template.alert_message,
        template.summary,
        template.impacted_service,
        *template.signatures,
        *template.symptoms,
        *(event["event_type"] for event in template.log_events),
        *(metric["metric"] for metric in template.metric_series),
        *ROOT_CAUSE_ALIASES.get(template.root_cause, ()),
    ]
    for term in terms:
        normalized = normalize_text(term)
        if normalized and normalized in text:
            score += 10
            matched.append(str(term))
    if normalize_text(template.root_cause) in text:
        score += 20
    return score, sorted(set(matched))


def match_report_template(message: str, incident_type: str | None = None) -> dict[str, Any]:
    """Find the best synthetic template for a user report."""

    if incident_type and incident_type not in {"", "random", "any"}:
        normalized_type = incident_type.strip().lower()
        for template in TEMPLATES:
            if template.key == normalized_type:
                return {"template": template, "score": 100, "matched_terms": [template.key]}

    text = normalize_text(message)
    ranked = []
    for template in TEMPLATES:
        score, matched_terms = _score_template(template, text)
        ranked.append({"template": template, "score": score, "matched_terms": matched_terms})
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[0]


def infer_severity(message: str, fallback: str = "warning") -> str:
    text = normalize_text(message)
    for severity, terms in SEVERITY_TERMS.items():
        if any(term in text for term in terms):
            return severity
    return fallback


def _source_for_template(template: IncidentTemplate | None) -> str:
    if template is None:
        return "user-report"
    return TOPOLOGY.get(template.topology_role, template.topology_role)


def _ensure_structured_incident(payload: dict[str, Any]) -> dict[str, Any]:
    incident = dict(payload["incident"])
    incident.setdefault("incident_id", payload.get("incident_id") or _new_incident_id())
    incident.setdefault("category", incident.get("category", "unknown"))
    incident.setdefault("title", incident.get("title", "User submitted incident"))
    incident.setdefault("generated_at", _iso(_now()))
    incident.setdefault("alert", {})
    incident.setdefault("logs", [])
    incident.setdefault("metrics", [])
    incident.setdefault("topology", {})
    incident.setdefault("recent_changes", incident.get("change_history", []))
    incident.setdefault("change_history", incident.get("recent_changes", []))
    incident.setdefault("baseline", {})
    return incident


def _manual_incident(payload: dict[str, Any], message: str, severity: str) -> dict[str, Any]:
    observed_at = _now()
    source = str(payload.get("source") or payload.get("device") or "manual-input")
    incident = {
        "incident_id": payload.get("incident_id") or _new_incident_id(),
        "category": payload.get("category") or "unknown",
        "title": payload.get("title") or "Manual incident intake",
        "generated_at": _iso(observed_at),
        "ground_truth_root_cause": payload.get("ground_truth_root_cause"),
        "alert": {
            "timestamp": _iso(observed_at),
            "severity": severity,
            "message": payload.get("alert_message") or message[:240],
            "source": source,
        },
        "metrics": list(payload.get("metrics") or []),
        "logs": list(payload.get("logs") or []),
        "topology": {"reported_source": source},
        "recent_changes": list(payload.get("recent_changes") or payload.get("change_history") or []),
        "baseline": dict(payload.get("baseline") or {}),
        "intake": {
            "source": "user_report",
            "reporter": payload.get("reporter") or payload.get("user") or "operator",
            "message": message,
            "matched_template": None,
            "match_score": 0,
            "matched_terms": [],
        },
    }
    incident["logs"].append(
        {
            "timestamp": _iso(observed_at),
            "source": source,
            "event_type": "manual_intake",
            "severity": severity,
            "message": message[:240],
            "role": "evidence",
            "signal": "related",
        }
    )
    if payload.get("change"):
        incident["recent_changes"].append(
            {
                "time": _iso(observed_at - timedelta(minutes=5)),
                "device": source,
                "action": str(payload["change"]),
                "actor": payload.get("reporter") or "operator",
                "status": "reported",
            }
        )
    incident["change_history"] = list(incident["recent_changes"])
    return incident


def build_incident_from_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Build an incident payload from structured JSON or free text."""

    if payload.get("incident"):
        incident = _ensure_structured_incident(payload)
        return {
            "incident": incident,
            "intake": {
                "source": "structured_incident",
                "matched_template": incident.get("scenario_key"),
                "match_score": None,
                "matched_terms": [],
            },
        }

    message = str(payload.get("message") or payload.get("text") or payload.get("description") or "").strip()
    if not message:
        raise ValueError("Missing required field: message or incident")

    match = match_report_template(message, payload.get("incident_type"))
    template = match["template"]
    severity = str(payload.get("severity") or infer_severity(message, template.severity))
    seed = int(payload["seed"]) if payload.get("seed") is not None else random.SystemRandom().randint(1, 10_000_000)
    incident_id = payload.get("incident_id") or _new_incident_id()

    if int(match["score"]) <= 0 and not payload.get("incident_type"):
        incident = _manual_incident(payload, message, severity)
        return {"incident": incident, "intake": incident["intake"]}

    incident = generate_incident(incident_id=incident_id, template=template, seed=seed)
    observed_at = _now()
    source = str(payload.get("source") or payload.get("device") or _source_for_template(template))
    summary = message[:240]

    incident["title"] = payload.get("title") or f"User reported incident mapped to {template.root_cause}"
    incident["alert"] = {
        "timestamp": _iso(observed_at),
        "severity": severity,
        "message": payload.get("alert_message") or summary,
        "source": source,
    }
    incident["intake"] = {
        "source": "user_report",
        "reporter": payload.get("reporter") or payload.get("user") or "operator",
        "message": message,
        "matched_template": template.key,
        "match_score": match["score"],
        "matched_terms": match["matched_terms"],
    }
    incident["logs"].append(
        {
            "timestamp": _iso(observed_at - timedelta(minutes=1)),
            "source": source,
            "event_type": "user_report",
            "severity": severity,
            "message": summary,
            "role": "evidence",
            "signal": "related",
        }
    )
    incident["logs"] = sorted(incident["logs"], key=lambda item: item.get("timestamp", ""))
    incident["topology"]["reported_source"] = source

    if payload.get("metrics"):
        incident["metrics"].extend(payload["metrics"])
    if payload.get("logs"):
        incident["logs"].extend(payload["logs"])
        incident["logs"] = sorted(incident["logs"], key=lambda item: item.get("timestamp", ""))
    if payload.get("recent_changes") or payload.get("change_history"):
        incident["recent_changes"].extend(payload.get("recent_changes") or payload.get("change_history") or [])
    elif payload.get("change"):
        incident["recent_changes"].append(
            {
                "time": _iso(observed_at - timedelta(minutes=5)),
                "device": source,
                "action": str(payload["change"]),
                "actor": payload.get("reporter") or "operator",
                "status": "reported",
            }
        )
    incident["change_history"] = list(incident["recent_changes"])
    return {"incident": incident, "intake": incident["intake"]}
