"""Normalize user-reported incidents into the synthetic incident contract."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
import unicodedata
from typing import Any

from .catalog import TEMPLATES, IncidentTemplate
from .generator import TOPOLOGY, generate_incident


ROOT_CAUSE_ALIASES = {
    "Broadcast Loop": ("vong lap", "loop", "broadcast storm", "mac flapping", "storm", "arp flood"),
    "STP Failure": ("stp", "spanning tree", "bpdu", "root bridge", "topology change"),
    "Interface Flapping": (
        "flapping",
        "flap",
        "link up down",
        "port up down",
        "cong chap chon",
        "interface flap",
        "port flap",
        "ge 0/0/1",
    ),
    "Mistaken Camera Access Port Shutdown": (
        "camera",
        "camera 01",
        "cam 01",
        "cam01",
        "cctv",
        "vms",
        "nvr",
        "camera down",
        "camera offline",
        "camera unreachable",
        "camera mat ket noi",
        "mat ket noi camera",
        "mat camera",
        "khong xem duoc camera",
        "port camera",
        "switch port camera",
        "poe camera",
        "rtsp",
        "heartbeat camera",
        "camera heartbeat",
        "ge 0/0/1",
    ),
    "Routing Issue": ("routing", "route", "bgp", "ospf", "mat route", "routing loop"),
    "Firewall Session Exhaustion": ("firewall", "fortigate", "session", "session spike", "session exhaustion"),
    "DNS Failure": ("dns", "resolve", "khong phan giai", "nxdomain", "dns timeout"),
    "Internet Congestion": (
        "internet cham",
        "congestion",
        "wan",
        "isp",
        "latency",
        "packet loss",
        "ket noi cham",
        "mang cham",
        "slow internet",
        "internet slow",
    ),
    "Disk Full": ("disk full", "day disk", "o dia day", "no space", "filesystem full"),
    "CPU Exhaustion": ("cpu high", "cpu cao", "cpu exhaustion", "load average", "high load"),
    "Memory Leak": ("memory leak", "ram tang", "oom", "out of memory", "bo nho"),
    "Service Crash": (
        "service crash",
        "crash",
        "process exited",
        "service down",
        "dich vu dung",
        "mat ket noi server",
        "khong ket noi server",
        "server unreachable",
        "connection refused",
        "database down",
        "db down",
        "db 01",
        "db-01",
    ),
    "VMware Datastore Full": ("datastore", "vmware datastore", "ds full", "thin provision"),
    "VMware Host Failure": ("esxi", "vmware host", "host failure", "ha failover", "host down"),
    "Brute Force Attack": ("brute force", "login failed", "failed login", "dang nhap that bai", "ssh failed"),
    "Malware Activity": ("malware", "virus", "ransomware", "ioc", "suspicious process"),
    "Port Scanning": ("port scan", "scan port", "quet cong", "nmap", "connection sweep"),
    "Lateral Movement": ("lateral", "di chuyen ngang", "smb", "psexec", "remote admin"),
}


SEVERITY_TERMS = {
    "critical": ("critical", "crit", "nghiem trong", "khong truy cap", "outage", "mat dich vu"),
    "high": ("high", "cao", "anh huong nhieu", "major"),
    "warning": ("warning", "canh bao", "medium", "trung binh", "degraded"),
    "info": ("info", "low", "thap", "minor"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _new_incident_id(prefix: str = "INC-USER") -> str:
    timestamp = _now().strftime("%Y%m%d%H%M%S")
    suffix = random.SystemRandom().randint(100, 999)
    return f"{prefix}-{timestamp}-{suffix}"


def _normalize_text(value: Any) -> str:
    text = str(value or "").lower().replace("đ", "d")
    text = "".join(
        char for char in unicodedata.normalize("NFD", text) if unicodedata.category(char) != "Mn"
    )
    replacements = {
        "á": "a",
        "à": "a",
        "ả": "a",
        "ã": "a",
        "ạ": "a",
        "ă": "a",
        "ắ": "a",
        "ằ": "a",
        "ẳ": "a",
        "ẵ": "a",
        "ặ": "a",
        "â": "a",
        "ấ": "a",
        "ầ": "a",
        "ẩ": "a",
        "ẫ": "a",
        "ậ": "a",
        "é": "e",
        "è": "e",
        "ẻ": "e",
        "ẽ": "e",
        "ẹ": "e",
        "ê": "e",
        "ế": "e",
        "ề": "e",
        "ể": "e",
        "ễ": "e",
        "ệ": "e",
        "í": "i",
        "ì": "i",
        "ỉ": "i",
        "ĩ": "i",
        "ị": "i",
        "ó": "o",
        "ò": "o",
        "ỏ": "o",
        "õ": "o",
        "ọ": "o",
        "ô": "o",
        "ố": "o",
        "ồ": "o",
        "ổ": "o",
        "ỗ": "o",
        "ộ": "o",
        "ơ": "o",
        "ớ": "o",
        "ờ": "o",
        "ở": "o",
        "ỡ": "o",
        "ợ": "o",
        "ú": "u",
        "ù": "u",
        "ủ": "u",
        "ũ": "u",
        "ụ": "u",
        "ư": "u",
        "ứ": "u",
        "ừ": "u",
        "ử": "u",
        "ữ": "u",
        "ự": "u",
        "ý": "y",
        "ỳ": "y",
        "ỷ": "y",
        "ỹ": "y",
        "ỵ": "y",
        "đ": "d",
    }
    for src, dst in replacements.items():
        text = text.replace(src, dst)
    return text.replace("_", " ").replace("-", " ")


def normalize_text(value: Any) -> str:
    """Public wrapper used by chat intake code."""

    return _normalize_text(value)


def _score_template(template: IncidentTemplate, text: str) -> tuple[int, list[str]]:
    score = 0
    matched: list[str] = []
    candidate_terms = [
        template.key,
        template.root_cause,
        template.category,
        template.alert_message,
        *template.signatures,
        *template.log_events,
        *(metric[1] for metric in template.metric_points),
        *ROOT_CAUSE_ALIASES.get(template.root_cause, ()),
    ]
    for term in candidate_terms:
        normalized = _normalize_text(term)
        if normalized and normalized in text:
            matched.append(str(term))
            score += 10
    if _normalize_text(template.root_cause) in text:
        score += 20
    return score, sorted(set(matched))


def match_report_template(message: str, incident_type: str | None = None) -> dict[str, Any]:
    """Find the best synthetic template for a user report."""

    if incident_type and incident_type not in {"", "random", "any"}:
        normalized_type = incident_type.strip().lower()
        for template in TEMPLATES:
            if template.key == normalized_type:
                return {"template": template, "score": 100, "matched_terms": [template.key]}

    text = _normalize_text(message)
    ranked = []
    for template in TEMPLATES:
        score, matched_terms = _score_template(template, text)
        ranked.append({"template": template, "score": score, "matched_terms": matched_terms})
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[0]


def infer_severity(message: str, fallback: str = "warning") -> str:
    text = _normalize_text(message)
    for severity, terms in SEVERITY_TERMS.items():
        if any(term in text for term in terms):
            return severity
    return fallback


def _source_for_template(template: IncidentTemplate | None) -> str:
    if template is None:
        return "user-report"
    return TOPOLOGY.get(template.topology_role, template.topology_role.upper())


def _ensure_structured_incident(payload: dict[str, Any]) -> dict[str, Any]:
    incident = dict(payload["incident"])
    incident.setdefault("incident_id", payload.get("incident_id") or _new_incident_id())
    incident.setdefault("category", incident.get("category", "unknown"))
    incident.setdefault("title", incident.get("title", "User submitted incident"))
    incident.setdefault("generated_at", _iso(_now()))
    incident.setdefault("alert", {})
    incident.setdefault("metrics", [])
    incident.setdefault("logs", [])
    incident.setdefault("topology", {})
    incident.setdefault("change_history", [])
    return incident


def build_incident_from_report(payload: dict[str, Any]) -> dict[str, Any]:
    """Build an incident payload from either structured JSON or a free-text report."""

    if payload.get("incident"):
        incident = _ensure_structured_incident(payload)
        return {
            "incident": incident,
            "intake": {
                "source": "structured_incident",
                "matched_template": None,
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
    observed_at = _now()

    if match["score"] <= 0 and not payload.get("incident_type"):
        source = str(payload.get("source") or payload.get("device") or "manual-input")
        incident = {
            "incident_id": incident_id,
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
            "change_history": list(payload.get("change_history") or []),
            "intake": {
                "source": "user_report",
                "reporter": payload.get("reporter") or payload.get("user") or "operator",
                "message": message,
                "matched_template": None,
                "match_score": match["score"],
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
            }
        )
        if payload.get("change"):
            incident["change_history"].append(
                {
                    "time": _iso(observed_at - timedelta(minutes=5)),
                    "device": source,
                    "action": str(payload["change"]),
                    "actor": payload.get("reporter") or "operator",
                }
            )
        return {"incident": incident, "intake": incident["intake"]}

    incident = generate_incident(incident_id=incident_id, template=template, seed=seed)
    source = str(payload.get("source") or payload.get("device") or _source_for_template(template))
    summary = message[:240]

    incident["title"] = payload.get("title") or f"User reported incident: {template.root_cause}"
    incident["category"] = payload.get("category") or template.category
    incident["ground_truth_root_cause"] = payload.get("ground_truth_root_cause")
    incident["intake"] = {
        "source": "user_report",
        "reporter": payload.get("reporter") or payload.get("user") or "operator",
        "message": message,
        "matched_template": template.key,
        "match_score": match["score"],
        "matched_terms": match["matched_terms"],
    }
    incident["alert"] = {
        "timestamp": _iso(observed_at),
        "severity": severity,
        "message": payload.get("alert_message") or summary,
        "source": source,
    }
    incident["logs"].append(
        {
            "timestamp": _iso(observed_at - timedelta(minutes=1)),
            "source": source,
            "event_type": "user_report",
            "severity": severity,
            "message": summary,
        }
    )
    incident["logs"] = sorted(incident["logs"], key=lambda item: item["timestamp"])
    incident["topology"]["reported_source"] = source

    if payload.get("metrics"):
        incident["metrics"].extend(payload["metrics"])
    if payload.get("logs"):
        incident["logs"].extend(payload["logs"])
        incident["logs"] = sorted(incident["logs"], key=lambda item: item.get("timestamp", ""))
    if payload.get("change_history"):
        incident["change_history"].extend(payload["change_history"])
    elif payload.get("change"):
        incident["change_history"].append(
            {
                "time": _iso(observed_at - timedelta(minutes=5)),
                "device": source,
                "action": str(payload["change"]),
                "actor": payload.get("reporter") or "operator",
            }
        )

    return {
        "incident": incident,
        "intake": incident["intake"],
    }
