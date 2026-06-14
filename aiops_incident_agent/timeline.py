"""Timeline builder for incident payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


ALLOWED_TYPES = {"change", "symptom", "impact", "evidence", "root_cause_candidate"}


def _parse_time(value: Any) -> datetime:
    if not value:
        return datetime.max.replace(tzinfo=timezone.utc)
    normalized = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(normalized).astimezone(timezone.utc)
    except ValueError:
        return datetime.max.replace(tzinfo=timezone.utc)


def _event(
    event_id: str,
    timestamp: str,
    source: str,
    event: str,
    event_type: str,
    category: str,
    signal: str = "related",
    severity: str = "info",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    event_category = category if category in ALLOWED_TYPES else "evidence"
    return {
        "event_id": event_id,
        "time": timestamp,
        "timestamp": timestamp,
        "event": event,
        "message": event,
        "source": source,
        "type": event_category,
        "category": event_category,
        "event_type": event_type,
        "severity": severity,
        "signal": signal,
        "details": details or {},
    }


def _change_items(incident: dict[str, Any]) -> list[dict[str, Any]]:
    if incident.get("recent_changes"):
        return list(incident.get("recent_changes") or [])
    return list(incident.get("change_history") or [])


def _metric_text(metric: dict[str, Any]) -> str:
    name = metric.get("metric", "metric")
    value = metric.get("value")
    unit = metric.get("unit", "")
    phase = metric.get("phase", "during")
    threshold = metric.get("threshold")
    text = f"{phase} {name}={value}{unit}"
    if threshold is not None:
        text += f" threshold={threshold}{unit}"
    if metric.get("breach"):
        text += " breached"
    return text


def _classify_metric(metric: dict[str, Any]) -> str:
    if metric.get("breach"):
        return "symptom"
    return "evidence"


def _classify_log(log: dict[str, Any]) -> str:
    role = str(log.get("role", "")).strip()
    if role in ALLOWED_TYPES:
        return role
    if role == "noise":
        return "evidence"
    event_type = str(log.get("event_type", "")).lower()
    message = str(log.get("message", "")).lower()
    if "impact" in event_type or "impact" in message or "user" in event_type:
        return "impact"
    if any(term in event_type for term in ("change", "policy", "config", "snapshot_growth", "prefix_denied")):
        return "root_cause_candidate"
    if any(term in event_type for term in ("failed", "high", "low", "spike", "storm", "flap", "crash", "timeout")):
        return "symptom"
    return "evidence"


def build_timeline(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a normalized, time-sorted incident timeline."""

    events: list[dict[str, Any]] = []
    counter = 1

    for change in _change_items(incident):
        timestamp = change.get("timestamp") or change.get("time")
        if not timestamp:
            continue
        events.append(
            _event(
                event_id=f"evt-{counter:03d}",
                timestamp=str(timestamp),
                source=str(change.get("device", "unknown")),
                event=str(change.get("action", "Configuration change")),
                event_type="change",
                category="change",
                signal="related",
                severity=str(change.get("severity", "info")),
                details={"actor": change.get("actor"), "change_id": change.get("change_id"), "status": change.get("status")},
            )
        )
        counter += 1

    for log in incident.get("logs", []) or []:
        timestamp = log.get("timestamp")
        if not timestamp:
            continue
        event_type = str(log.get("event_type", "log"))
        events.append(
            _event(
                event_id=f"evt-{counter:03d}",
                timestamp=str(timestamp),
                source=str(log.get("source", "unknown")),
                event=str(log.get("message") or event_type),
                event_type=event_type,
                category=_classify_log(log),
                signal=str(log.get("signal", "related")),
                severity=str(log.get("severity", "info")),
                details={"role": log.get("role")},
            )
        )
        counter += 1

    for metric in incident.get("metrics", []) or []:
        timestamp = metric.get("timestamp")
        if not timestamp:
            continue
        metric_name = str(metric.get("metric", "metric"))
        events.append(
            _event(
                event_id=f"evt-{counter:03d}",
                timestamp=str(timestamp),
                source=str(metric.get("source", "unknown")),
                event=_metric_text(metric),
                event_type=metric_name,
                category=_classify_metric(metric),
                signal="related" if metric.get("breach") or metric.get("phase") in {"during", "after"} else "baseline",
                severity="warning" if metric.get("breach") else "info",
                details={
                    "metric": metric_name,
                    "value": metric.get("value"),
                    "threshold": metric.get("threshold"),
                    "unit": metric.get("unit"),
                    "phase": metric.get("phase"),
                    "breach": metric.get("breach"),
                },
            )
        )
        counter += 1

    alert = incident.get("alert") or {}
    if alert.get("timestamp"):
        events.append(
            _event(
                event_id=f"evt-{counter:03d}",
                timestamp=str(alert["timestamp"]),
                source=str(alert.get("source", "alert")),
                event=str(alert.get("message", "Alert triggered")),
                event_type="alert",
                category="symptom",
                signal="related",
                severity=str(alert.get("severity", "unknown")),
            )
        )

    return sorted(events, key=lambda item: (_parse_time(item["time"]), item["event_id"]))
