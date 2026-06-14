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


def _short_text(value: Any, limit: int = 96) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."


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
        message = _safe(_short_text(event.get("message", ""), 110))
        lines.append(f"• <code>{timestamp}</code> · <b>{event_type}</b> · <code>{source}</code>")
        if message:
            lines.append(f"  {message}")
    return lines


def _hypothesis_lines(root: dict[str, Any], limit: int = 3) -> list[str]:
    hypotheses = root.get("hypothesis_summary") or []
    if not hypotheses:
        return ["• <i>No hypothesis ranking available</i>"]

    lines = []
    for index, item in enumerate(hypotheses[:limit], start=1):
        cause = _safe(item.get("root_cause", "Unknown"))
        probability = _safe(item.get("probability", 0))
        evidence = item.get("evidence") or []
        evidence_text = f" · {_safe(', '.join(map(str, evidence[:2])))}" if evidence else ""
        lines.append(f"{index}. <b>{cause}</b> · <code>{probability}%</code>{evidence_text}")
    return lines


def format_telegram_report(assessment: dict[str, Any]) -> str:
    root = assessment.get("root_cause_analysis", {})
    rec = assessment.get("recommendations", {})
    timeline = assessment.get("timeline", [])
    severity = assessment.get("severity", "unknown")
    method = root.get("method", "heuristic")
    model = root.get("llm_model", "")
    immediate = rec.get("immediate_actions", [])

    lines = [
        "🚨 <b>AIOps Incident Assessment</b>",
        f"{_severity_badge(str(severity))} · <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        f"Category: <b>{_safe(assessment.get('category', 'unknown')).title()}</b>",
        "",
        "🎯 <b>RCA Summary</b>",
        f"Most likely: <code>{_safe(root.get('root_cause', 'Unknown'))}</code>",
        f"Confidence: {_confidence_badge(root.get('confidence', 0))}",
        "",
        "🧠 <b>Hypotheses</b>",
    ]
    lines.extend(_hypothesis_lines(root, limit=3))
    lines.extend(
        [
            "",
            "🕒 <b>Timeline Snapshot</b>",
        ]
    )
    lines.extend(_timeline_lines(timeline, limit=4))
    lines.extend(
        [
            "",
            "⚡ <b>Next Action</b>",
        ]
    )
    lines.append(f"1. {_safe(immediate[0] if immediate else 'Preserve evidence and verify alert state')}")
    lines.extend(
        [
            "",
            f"Method: <code>{_safe(method)}</code>" + (f" · Model: <code>{_safe(model)}</code>" if model else ""),
            f"Status: <b>{_safe(assessment.get('status', 'Need verification'))}</b>",
            "",
            "<i>Use the buttons below for full timeline, evidence, and actions.</i>",
        ]
    )
    return "\n".join(lines)


def format_telegram_timeline_detail(assessment: dict[str, Any]) -> str:
    lines = [
        "🕒 <b>Incident Timeline</b>",
        f"Incident: <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        "",
    ]
    lines.extend(_timeline_lines(assessment.get("timeline", []), limit=12))
    return "\n".join(lines)


def format_telegram_evidence_detail(assessment: dict[str, Any]) -> str:
    root = assessment.get("root_cause_analysis", {})
    timeline = assessment.get("timeline", [])
    evidence = _collect_evidence(root, timeline)
    lines = [
        "🧾 <b>Evidence Detail</b>",
        f"Incident: <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        "",
        "🧠 <b>Hypothesis Ranking</b>",
    ]
    lines.extend(_hypothesis_lines(root, limit=5))
    lines.extend(["", "Signals:"])
    lines.extend(_item_lines(evidence, limit=12, icon="•"))
    if root.get("evidence"):
        lines.extend(["", "LLM Evidence:"])
        lines.extend(_item_lines(root.get("evidence", []), limit=8, icon="•"))
    return "\n".join(lines)


def format_telegram_actions_detail(assessment: dict[str, Any]) -> str:
    rec = assessment.get("recommendations", {})
    lines = [
        "⚡ <b>Recommended Actions</b>",
        f"Incident: <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        "",
        "Immediate:",
    ]
    lines.extend(_numbered_lines(rec.get("immediate_actions", []), limit=6))
    lines.extend(["", "Verification:"])
    lines.extend(_item_lines(rec.get("verification_actions", []), limit=6, icon="•"))
    lines.extend(["", "Long-term Prevention:"])
    lines.extend(_item_lines(rec.get("long_term_prevention", []), limit=6, icon="•"))
    return "\n".join(lines)


def format_telegram_full_detail(assessment: dict[str, Any]) -> str:
    parts = [
        format_telegram_evidence_detail(assessment),
        "",
        format_telegram_timeline_detail(assessment),
        "",
        format_telegram_actions_detail(assessment),
    ]
    text = "\n".join(parts)
    if len(text) > 3800:
        return text[:3790].rstrip() + "\n..."
    return text


def format_telegram_detail(assessment: dict[str, Any], section: str) -> str:
    if section == "tl":
        return format_telegram_timeline_detail(assessment)
    if section == "ev":
        return format_telegram_evidence_detail(assessment)
    if section == "ac":
        return format_telegram_actions_detail(assessment)
    return format_telegram_full_detail(assessment)


def telegram_action_keyboard(incident_id: str | None) -> dict[str, Any] | None:
    if not incident_id:
        return None
    safe_id = str(incident_id)[:48]
    return {
        "inline_keyboard": [
            [
                {"text": "Timeline", "callback_data": f"rca:tl:{safe_id}"},
                {"text": "Evidence", "callback_data": f"rca:ev:{safe_id}"},
            ],
            [
                {"text": "Actions", "callback_data": f"rca:ac:{safe_id}"},
                {"text": "Full", "callback_data": f"rca:full:{safe_id}"},
            ],
        ]
    }


def format_telegram_payload(text: str, reply_markup: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build the Telegram API payload for rich HTML rendering."""

    payload = {
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return payload


def send_telegram_report(
    text: str,
    chat_id: str | int | None = None,
    reply_markup: dict[str, Any] | None = None,
) -> dict[str, Any]:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    target_chat_id = str(chat_id) if chat_id is not None else os.getenv("TELEGRAM_CHAT_ID")
    if _is_placeholder(token) or _is_placeholder(target_chat_id):
        return {"sent": False, "reason": "TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not configured"}

    try:
        import requests

        payload = format_telegram_payload(text, reply_markup=reply_markup)
        payload["chat_id"] = target_chat_id
        response = requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=10,
        )
        return {"sent": response.ok, "status_code": response.status_code, "response": response.text[:500]}
    except Exception as exc:  # pragma: no cover - network defensive path
        return {"sent": False, "reason": str(exc)}


def answer_callback_query(callback_query_id: str | None, text: str = "") -> dict[str, Any]:
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if _is_placeholder(token) or not callback_query_id:
        return {"sent": False, "reason": "TELEGRAM_BOT_TOKEN or callback_query_id is not configured"}

    try:
        import requests

        response = requests.post(
            f"https://api.telegram.org/bot{token}/answerCallbackQuery",
            json={"callback_query_id": callback_query_id, "text": text[:180]},
            timeout=10,
        )
        return {"sent": response.ok, "status_code": response.status_code, "response": response.text[:500]}
    except Exception as exc:  # pragma: no cover - network defensive path
        return {"sent": False, "reason": str(exc)}
