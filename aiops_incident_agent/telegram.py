"""Telegram report formatting and optional delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import os
from typing import Any


def _is_placeholder(value: str | None) -> bool:
    return not value or value.strip().upper().startswith("REPLACE_ME")


def _safe(value: Any, default: str = "unknown") -> str:
    if value is None or value == "":
        return escape(default)
    return escape(str(value), quote=False)


def _severity_badge(severity: str) -> str:
    normalized = severity.lower()
    if normalized == "critical":
        return "🔴 <b>CRITICAL</b>"
    if normalized in {"high", "major"}:
        return "🟠 <b>HIGH</b>"
    if normalized in {"warning", "medium"}:
        return "🟡 <b>WARNING</b>"
    if normalized in {"low", "info", "informational"}:
        return "🟢 <b>INFO</b>"
    return f"⚪ <b>{_safe(severity).upper()}</b>"


def _confidence_badge(confidence: Any) -> str:
    try:
        value = int(confidence)
    except (TypeError, ValueError):
        value = 0

    if value >= 85:
        label = "🟢 High"
    elif value >= 70:
        label = "🟡 Medium"
    else:
        label = "🟠 Low"
    return f"{label} · <b>{value}%</b>"


def _short_time(value: Any) -> str:
    if not value:
        return "unknown"
    try:
        normalized = str(value).replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized).astimezone(timezone.utc)
        return parsed.strftime("%H:%M:%S UTC")
    except ValueError:
        return str(value)


def _item_lines(items: list[Any], limit: int, icon: str) -> list[str]:
    if not items:
        return [f"{icon} <i>No data available</i>"]
    return [f"{icon} {_safe(item)}" for item in items[:limit]]


def _numbered_lines(items: list[Any], limit: int) -> list[str]:
    if not items:
        return ["1. <i>No data available</i>"]
    return [f"{index}. {_safe(item)}" for index, item in enumerate(items[:limit], start=1)]


def _collect_evidence(root: dict[str, Any], timeline: list[dict[str, Any]]) -> list[str]:
    evidence: list[str] = []
    for item in root.get("ranked_hypotheses", [])[:1]:
        evidence.extend(item.get("evidence", []))
    if evidence:
        return sorted(set(str(item) for item in evidence))
    return [event.get("event_type", "event") for event in timeline[:5]]


def _timeline_lines(timeline: list[dict[str, Any]], limit: int = 6) -> list[str]:
    if not timeline:
        return ["• <i>No timeline events available</i>"]

    lines = []
    for event in timeline[:limit]:
        timestamp = _safe(_short_time(event.get("timestamp")))
        event_type = _safe(event.get("event_type", "event"))
        source = _safe(event.get("source", "unknown"))
        message = _safe(event.get("message", ""))
        lines.append(f"• <code>{timestamp}</code> · <b>{event_type}</b> · <code>{source}</code>")
        if message:
            lines.append(f"  {message}")
    return lines


def format_telegram_report(assessment: dict[str, Any]) -> str:
    root = assessment.get("root_cause_analysis", {})
    rec = assessment.get("recommendations", {})
    timeline = assessment.get("timeline", [])
    evidence = _collect_evidence(root, timeline)
    severity = assessment.get("severity", "unknown")
    method = root.get("method", "heuristic")
    model = root.get("llm_model", "")

    lines = [
        "🚨 <b>AIOps Incident Assessment</b>",
        f"{_severity_badge(str(severity))} · <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        f"Category: <b>{_safe(assessment.get('category', 'unknown')).title()}</b>",
        "",
        "🎯 <b>Most Likely Root Cause</b>",
        f"<code>{_safe(root.get('root_cause', 'Unknown'))}</code>",
        f"Confidence: {_confidence_badge(root.get('confidence', 0))}",
        f"Method: <code>{_safe(method)}</code>" + (f" · Model: <code>{_safe(model)}</code>" if model else ""),
        "",
        "🧾 <b>Evidence</b>",
    ]
    lines.extend(_item_lines(evidence, limit=8, icon="•"))
    lines.extend(
        [
            "",
            "🕒 <b>Timeline</b>",
        ]
    )
    lines.extend(_timeline_lines(timeline))
    lines.extend(
        [
            "",
            "⚡ <b>Immediate Actions</b>",
        ]
    )
    lines.extend(_numbered_lines(rec.get("immediate_actions", []), limit=5))
    lines.extend(
        [
            "",
            "✅ <b>Verification</b>",
        ]
    )
    lines.extend(_item_lines(rec.get("verification_actions", []), limit=4, icon="•"))
    lines.extend(
        [
            "",
            "🛡️ <b>Long-term Prevention</b>",
        ]
    )
    lines.extend(_item_lines(rec.get("long_term_prevention", []), limit=3, icon="•"))
    lines.extend(
        [
            "",
            f"Status: <b>{_safe(assessment.get('status', 'Need verification'))}</b>",
        ]
    )
    return "\n".join(lines)


def format_telegram_payload(text: str) -> dict[str, Any]:
    """Build the Telegram API payload for rich HTML rendering."""

    return {
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }


def send_telegram_report(text: str, chat_id: str | int | None = None) -> dict[str, Any]:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    target_chat_id = str(chat_id) if chat_id is not None else os.getenv("TELEGRAM_CHAT_ID")
    if _is_placeholder(token) or _is_placeholder(target_chat_id):
        return {"sent": False, "reason": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured"}

    try:
        import requests

        payload = format_telegram_payload(text)
        payload["chat_id"] = target_chat_id
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=10,
        )
        return {"sent": response.ok, "status_code": response.status_code, "response": response.text[:500]}
    except Exception as exc:  # pragma: no cover - network defensive path
        return {"sent": False, "reason": str(exc)}
