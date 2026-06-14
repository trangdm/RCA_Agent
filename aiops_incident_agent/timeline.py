"""Timeline builder for incident payloads."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def _parse_time(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized).astimezone(timezone.utc)


def _event(event_id: str, timestamp: str, source: str, event_type: str, message: str, category: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "message": message,
        "category": category,
    }


def build_timeline(incident: dict[str, Any]) -> list[dict[str, Any]]:
    """Build a normalized, time-sorted incident timeline."""

    events: list[dict[str, Any]] = []
    counter = 1

    for change in incident.get("change_history", []):
        timestamp = change.get("timestamp") or change.get("time")
        if not timestamp:
            continue
        events.append(
            _event(
                f"evt-{counter:03d}",
                timestamp,
                change.get("device", "unknown"),
                "change",
                change.get("action", "Configuration change"),
                "change",
            )
        )
        counter += 1

    for log in incident.get("logs", []):
        timestamp = log.get("timestamp")
        if not timestamp:
            continue
        events.append(
            _event(
                f"evt-{counter:03d}",
                timestamp,
                log.get("source", "unknown"),
                log.get("event_type", "log"),
                log.get("message", ""),
                "log",
            )
        )
        counter += 1

    for metric in incident.get("metrics", []):
        timestamp = metric.get("timestamp")
        if not timestamp:
            continue
        metric_name = metric.get("metric", "metric")
        value = metric.get("value")
        unit = metric.get("unit", "")
        threshold = metric.get("threshold")
        message = f"{metric_name}={value}{unit}"
        if threshold is not None:
            message += f" threshold={threshold}{unit}"
        events.append(
            _event(
                f"evt-{counter:03d}",
                timestamp,
                metric.get("source", "unknown"),
                metric_name,
                message,
                "metric",
            )
        )
        counter += 1

    alert = incident.get("alert") or {}
    if alert.get("timestamp"):
        events.append(
            _event(
                f"evt-{counter:03d}",
                alert["timestamp"],
                alert.get("source", "alert"),
                "alert",
                alert.get("message", ""),
                "alert",
            )
        )

    return sorted(events, key=lambda item: (_parse_time(item["timestamp"]), item["event_id"]))
