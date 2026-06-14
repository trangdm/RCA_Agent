"""Telegram report formatting and optional delivery."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import os
from typing import Any


ALERT_ICON = "\U0001f6a8"
RED = "\U0001f534"
ORANGE = "\U0001f7e0"
YELLOW = "\U0001f7e1"
GREEN = "\U0001f7e2"
WHITE = "\u26aa"


def _is_placeholder(value: str | None) -> bool:
    return not value or value.strip().upper().startswith("REPLACE_ME")


def _safe(value: Any, default: str = "unknown", limit: int | None = None) -> str:
    if value is None or value == "":
        text = default
    else:
        text = " ".join(str(value).split())
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return escape(text, quote=False)


def _severity_badge(severity: Any) -> str:
    normalized = str(severity or "").lower()
    if normalized == "critical":
        return f"{RED} <b>CRITICAL</b>"
    if normalized in {"major", "high"}:
        return f"{ORANGE} <b>MAJOR</b>"
    if normalized in {"warning", "medium"}:
        return f"{YELLOW} <b>WARNING</b>"
    if normalized in {"low", "info", "informational"}:
        return f"{GREEN} <b>INFO</b>"
    return f"{WHITE} <b>{_safe(severity).upper()}</b>"


def _short_time(value: Any) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        return parsed.strftime("%H:%M:%S UTC")
    except ValueError:
        return str(value)


def _numbered(items: list[Any], limit: int, empty: str) -> list[str]:
    if not items:
        return [f"1. <i>{_safe(empty)}</i>"]
    return [f"{index}. {_safe(item, limit=180)}" for index, item in enumerate(items[:limit], start=1)]


def _dash(items: list[Any], limit: int, empty: str) -> list[str]:
    if not items:
        return [f"- <i>{_safe(empty)}</i>"]
    return [f"- {_safe(item, limit=180)}" for item in items[:limit]]


def _timeline_lines(timeline: list[dict[str, Any]], limit: int = 7) -> list[str]:
    useful = [event for event in timeline if event.get("signal") not in {"noise", "baseline"}]
    if not useful:
        useful = timeline
    if not useful:
        return ["- <i>No timeline data available</i>"]

    lines = []
    for event in useful[:limit]:
        event_type = _safe(event.get("type", "event"))
        time = _safe(_short_time(event.get("time") or event.get("timestamp")))
        source = _safe(event.get("source", "unknown"))
        message = _safe(event.get("event") or event.get("message"), limit=150)
        lines.append(f"- <code>{time}</code> [{event_type}] <code>{source}</code>: {message}")
    if len(useful) > limit:
        lines.append(f"- ... {len(useful) - limit} more related events kept in JSON timeline")
    return lines


def format_telegram_report(assessment: dict[str, Any]) -> str:
    rec = assessment.get("recommended_actions") or assessment.get("recommendations") or {}
    hypotheses = assessment.get("root_cause_hypotheses") or []
    confidence = int(assessment.get("confidence") or 0)
    status = assessment.get("status", "need_verification")

    lines = [
        f"{ALERT_ICON} <b>AIOps RCA Alert</b>",
        "",
        f"<b>Incident ID:</b> <code>{_safe(assessment.get('incident_id', 'unknown'))}</code>",
        f"<b>Severity:</b> {_severity_badge(assessment.get('severity', 'unknown'))}",
        "",
        "<b>Summary:</b>",
        _safe(assessment.get("summary", "No summary available."), limit=700),
        "",
        "<b>Most Likely Root Cause:</b>",
        f"<code>{_safe(assessment.get('most_likely_root_cause', 'Undetermined'), limit=220)}</code>",
        "",
        "<b>Confidence:</b>",
        f"<b>{confidence}%</b>",
        "",
        "<b>Evidence:</b>",
    ]
    lines.extend(_numbered(list(assessment.get("evidence") or []), limit=6, empty="No concrete evidence yet"))

    if hypotheses:
        lines.extend(["", "<b>Root Cause Candidates:</b>"])
        for index, hypothesis in enumerate(hypotheses[:3], start=1):
            lines.append(
                f"{index}. {_safe(hypothesis.get('hypothesis'), limit=120)} "
                f"(<b>{int(hypothesis.get('confidence') or 0)}%</b>)"
            )

    lines.extend(["", "<b>Timeline:</b>"])
    lines.extend(_timeline_lines(list(assessment.get("timeline") or [])))
    lines.extend(["", "<b>Impact:</b>", _safe(assessment.get("impact", "No explicit impact data."), limit=450)])
    lines.extend(["", "<b>Recommended Actions:</b>"])
    lines.extend(_numbered(list(rec.get("immediate_actions") or []), limit=4, empty="Preserve evidence and verify the alert state"))
    lines.extend(["", "<b>Verification Steps:</b>"])
    lines.extend(_dash(list(rec.get("verification_actions") or []), limit=5, empty="Collect more evidence before confirmation"))
    lines.extend(["", "<b>Missing Data:</b>"])
    lines.extend(_dash(list(assessment.get("missing_data") or []), limit=5, empty="No missing data listed"))
    lines.extend(["", "<b>Status:</b>", f"<code>{_safe(status)}</code>"])

    text = "\n".join(lines)
    if len(text) > 3900:
        return text[:3890].rstrip() + "\n..."
    return text


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
