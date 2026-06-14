"""AgentBase entrypoint for the AIOps Incident Investigation Agent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from html import escape
import random
import re
import sys

from dotenv import load_dotenv
from greennode_agentbase import GreenNodeAgentBaseApp, PingStatus, RequestContext

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_incident
from aiops_incident_agent.intake import build_incident_from_report, match_report_template, normalize_text
from aiops_incident_agent.catalog import TEMPLATES, TEMPLATES_BY_KEY, IncidentTemplate
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.telegram import send_telegram_report


load_dotenv()

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

app = GreenNodeAgentBaseApp()
INVESTIGATION_SESSIONS: dict[str, dict] = {}
INVESTIGATION_SESSION_LIMIT = 100


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _new_incident_id(prefix: str = "INC-DEMO") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = random.SystemRandom().randint(100, 999)
    return f"{prefix}-{timestamp}-{suffix}"


def _iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _html(value: object, default: str = "unknown") -> str:
    if value is None or value == "":
        return escape(default, quote=False)
    return escape(str(value), quote=False)


def _chat_key(chat_id: str | int | None) -> str | None:
    if chat_id is None:
        return None
    return str(chat_id)


def _template_from_payload(payload: dict) -> tuple[IncidentTemplate | None, str | None]:
    incident_type = str(payload.get("incident_type", "random")).strip().lower()
    if incident_type in {"", "random", "any"}:
        rng = random.Random(int(payload["seed"])) if payload.get("seed") is not None else random.SystemRandom()
        return rng.choice(TEMPLATES), None

    template = TEMPLATES_BY_KEY.get(incident_type)
    if template is None:
        return None, f"Unknown incident_type: {incident_type}"
    return template, None


def _generate_from_payload(payload: dict, default_prefix: str = "INC-DEMO") -> dict:
    template, error = _template_from_payload(payload)
    if error or template is None:
        return {"status": "error", "message": error}

    seed = payload.get("seed")
    if seed is None:
        seed = random.SystemRandom().randint(1, 10_000_000)

    incident = generate_incident(
        incident_id=payload.get("incident_id") or _new_incident_id(default_prefix),
        template=template,
        seed=int(seed),
    )
    return {
        "status": "success",
        "incident_type": template.key,
        "seed": int(seed),
        "incident": incident,
    }


def _analyst_reply(incident: dict, assessment: dict) -> str:
    root = assessment.get("root_cause_analysis", {})
    rec = assessment.get("recommendations", {})
    immediate = rec.get("immediate_actions", [])
    action_text = immediate[0] if immediate else "Preserve evidence and verify the alert state"
    return (
        f"Đã ghi nhận {incident.get('incident_id', 'incident')}. "
        f"Root cause khả năng cao nhất: {root.get('root_cause', 'Unknown')} "
        f"({root.get('confidence', 0)}%). "
        f"Hành động ưu tiên: {action_text}."
    )


def _short_time(value: object) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        return parsed.strftime("%H:%M:%S UTC")
    except ValueError:
        return str(value)


def _short_text(value: object, limit: int = 170) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "..."


def _extract_time_window(text: str) -> str | None:
    matches = re.findall(r"\b(\d{1,2})\s*(?::|h)\s*(\d{2})\b", text.lower())
    if len(matches) < 2:
        return None
    start_hour, start_minute = (int(part) for part in matches[0])
    end_hour, end_minute = (int(part) for part in matches[1])
    if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23 and 0 <= start_minute <= 59 and 0 <= end_minute <= 59):
        return None
    return f"{start_hour:02d}:{start_minute:02d}-{end_hour:02d}:{end_minute:02d}"


def _window_start(window: str) -> tuple[int, int] | None:
    match = re.match(r"^(\d{2}):(\d{2})-", window)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _parse_iso(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _format_iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _shift_timestamp(value: object, delta: timedelta) -> str | None:
    parsed = _parse_iso(value)
    if parsed is None:
        return None
    return _format_iso(parsed + delta)


def _align_incident_to_window(incident: dict, window: str | None) -> None:
    if not window:
        return
    start = _window_start(window)
    if not start:
        return

    timestamps = []
    for change in incident.get("change_history", []):
        timestamps.append(_parse_iso(change.get("time") or change.get("timestamp")))
    for log in incident.get("logs", []):
        timestamps.append(_parse_iso(log.get("timestamp")))
    for metric in incident.get("metrics", []):
        timestamps.append(_parse_iso(metric.get("timestamp")))
    alert = incident.get("alert") or {}
    timestamps.append(_parse_iso(alert.get("timestamp")))
    timestamps = [timestamp for timestamp in timestamps if timestamp is not None]
    if not timestamps:
        return

    earliest = min(timestamps)
    target_start = earliest.replace(hour=start[0], minute=start[1], second=0, microsecond=0)
    delta = target_start - earliest

    for change in incident.get("change_history", []):
        key = "time" if change.get("time") else "timestamp"
        shifted = _shift_timestamp(change.get(key), delta)
        if shifted:
            change[key] = shifted
    for log in incident.get("logs", []):
        shifted = _shift_timestamp(log.get("timestamp"), delta)
        if shifted:
            log["timestamp"] = shifted
    for metric in incident.get("metrics", []):
        shifted = _shift_timestamp(metric.get("timestamp"), delta)
        if shifted:
            metric["timestamp"] = shifted
    if alert.get("timestamp"):
        shifted = _shift_timestamp(alert.get("timestamp"), delta)
        if shifted:
            alert["timestamp"] = shifted


def _extract_entities(text: str) -> list[str]:
    patterns = [
        r"\b(?:[A-Za-z]{2,}[-_][A-Za-z0-9_-]+)\b",
        r"\b(?:ge|gi|xe|et)-?\d+/\d+/\d+\b",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
    ]
    entities: list[str] = []
    for pattern in patterns:
        entities.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return sorted(set(entities), key=lambda item: item.lower())[:8]


def _observation_type(text: str) -> str:
    normalized = normalize_text(text)
    if any(term in normalized for term in ("gia dinh", "nghi ngo", "nghi la", "co the do", "suspect", "hypothesis")):
        return "operator_hypothesis"
    if any(term in normalized for term in ("log", "error", "exception", "timeout", "denied", "failed", "drop", "reset")):
        return "operator_log"
    if any(term in normalized for term in ("impact", "anh huong", "user", "khach hang", "khong truy cap", "mat dich vu")):
        return "operator_impact"
    return "operator_observation"


def _start_new_investigation_text(text: str) -> str:
    stripped = re.sub(
        r"^\s*(/new|new incident|incident mới|incident moi|sự cố mới|su co moi|bắt đầu sự cố mới|bat dau su co moi)\s*[:\-]?\s*",
        "",
        text,
        flags=re.IGNORECASE,
    ).strip()
    return stripped or text


def _is_new_investigation_command(text: str) -> bool:
    normalized = normalize_text(text).strip()
    return normalized.startswith(("su co moi", "incident moi", "/new", "new incident", "bat dau su co moi"))


def _is_close_investigation_command(text: str) -> bool:
    normalized = normalize_text(text).strip()
    return normalized in {"/close", "/done", "dong su co", "ket thuc su co", "reset", "/reset"}


def _detect_focus(text: str) -> str:
    normalized = normalize_text(text)
    if any(term in normalized for term in ("change", "cau hinh", "config", "ai thuc hien", "audit")):
        return "change"
    if any(term in normalized for term in ("timeline", "log", "event", "su kien")):
        return "timeline"
    if any(term in normalized for term in ("root cause", "rca", "nguyen nhan", "gia dinh", "hypothesis", "bang chung", "evidence", "tai sao")):
        return "rca"
    if any(term in normalized for term in ("action", "xu ly", "khuyen nghi", "verify", "xac minh")):
        return "action"
    return "update"


def _session_notes(session: dict) -> list[str]:
    notes = []
    if session.get("time_windows"):
        notes.append("time window: " + ", ".join(session["time_windows"][-3:]))
    if session.get("entities"):
        notes.append("đối tượng nghi ngờ: " + ", ".join(session["entities"][-8:]))
    if session.get("operator_hypotheses"):
        notes.append("hypothesis operator: " + " | ".join(session["operator_hypotheses"][-2:]))
    return notes


def _build_session_incident(session: dict) -> dict:
    combined = "\n".join(item["text"] for item in session["messages"])
    payload = {
        "message": combined,
        "source": "telegram-chat",
        "incident_id": session["incident_id"],
        "seed": session["seed"],
        "send_telegram": False,
    }
    normalized = build_incident_from_report(payload)
    incident = normalized["incident"]
    _align_incident_to_window(incident, session["time_windows"][0] if session.get("time_windows") else None)
    incident.setdefault("investigation_context", {})
    incident["investigation_context"] = {
        "message_count": len(session["messages"]),
        "time_windows": session.get("time_windows", []),
        "entities": session.get("entities", []),
        "operator_hypotheses": session.get("operator_hypotheses", []),
    }
    for index, message in enumerate(session["messages"], start=1):
        incident["logs"].append(
            {
                "timestamp": message["timestamp"],
                "source": "operator",
                "event_type": message["kind"],
                "severity": "info",
                "message": f"Observation {index}: {_short_text(message['text'], 240)}",
            }
        )
    incident["logs"] = sorted(incident["logs"], key=lambda item: item.get("timestamp", ""))
    return {"incident": incident, "intake": normalized["intake"]}


def _append_session_message(session: dict, text: str) -> None:
    timestamp = _iso_now()
    kind = _observation_type(text)
    session["messages"].append({"timestamp": timestamp, "text": text, "kind": kind})
    session["updated_at"] = timestamp

    time_window = _extract_time_window(text)
    if time_window and time_window not in session["time_windows"]:
        session["time_windows"].append(time_window)

    for entity in _extract_entities(text):
        if entity not in session["entities"]:
            session["entities"].append(entity)

    if kind == "operator_hypothesis":
        session["operator_hypotheses"].append(text)


def _create_investigation_session(chat_id: str | int | None, text: str) -> dict:
    session = {
        "chat_id": _chat_key(chat_id),
        "incident_id": _new_incident_id("INC-INV"),
        "seed": random.SystemRandom().randint(1, 10_000_000),
        "created_at": _iso_now(),
        "updated_at": _iso_now(),
        "messages": [],
        "time_windows": [],
        "entities": [],
        "operator_hypotheses": [],
    }
    _append_session_message(session, text)
    key = _chat_key(chat_id)
    if key:
        INVESTIGATION_SESSIONS[key] = session
        while len(INVESTIGATION_SESSIONS) > INVESTIGATION_SESSION_LIMIT:
            oldest_key = next(iter(INVESTIGATION_SESSIONS))
            INVESTIGATION_SESSIONS.pop(oldest_key, None)
    return session


def _format_timeline_section(assessment: dict, limit: int = 6) -> list[str]:
    timeline = assessment.get("timeline", [])
    if not timeline:
        return ["• <i>Chưa có timeline event.</i>"]
    system_timeline = [
        event for event in timeline if event.get("source") != "operator" and not str(event.get("event_type", "")).startswith("operator_")
    ]
    display_events = system_timeline or timeline
    lines = []
    for event in display_events[:limit]:
        lines.append(
            f"• <code>{_html(_short_time(event.get('timestamp')))}</code> · "
            f"<b>{_html(event.get('event_type'))}</b> · <code>{_html(event.get('source'))}</code>"
        )
        if event.get("message"):
            lines.append(f"  {_html(_short_text(event.get('message'), 150))}")
    return lines


def _format_change_section(incident: dict) -> list[str]:
    changes = incident.get("change_history", [])
    if not changes:
        return ["• <i>Chưa thấy change/config event trong dữ liệu hiện có.</i>"]
    lines = []
    for change in changes[:6]:
        lines.append(
            f"• <code>{_html(_short_time(change.get('time') or change.get('timestamp')))}</code> · "
            f"<code>{_html(change.get('device'))}</code> · {_html(change.get('action'))}"
        )
    return lines


def _format_rca_section(assessment: dict) -> list[str]:
    root = assessment.get("root_cause_analysis", {})
    lines = [
        f"Root cause hiện tại: <code>{_html(root.get('root_cause', 'Unknown'))}</code>",
        f"Độ tin cậy: <b>{_html(root.get('confidence', 0))}%</b>",
    ]
    ranked = root.get("ranked_hypotheses") or []
    if ranked:
        lines.append("Giả định liên quan:")
        for item in ranked[:4]:
            evidence = ", ".join(map(str, item.get("evidence", [])[:3])) or "no strong signal"
            lines.append(f"• {_html(item.get('root_cause'))} · score <code>{_html(item.get('score', 0))}</code> · {_html(evidence)}")
    return lines


def _format_action_section(assessment: dict) -> list[str]:
    rec = assessment.get("recommendations", {})
    actions = rec.get("immediate_actions", [])
    if not actions:
        actions = ["Giữ nguyên hiện trạng, thu thập thêm log/metric/change trong incident window"]
    return [f"{index}. {_html(action)}" for index, action in enumerate(actions[:5], start=1)]


def _format_investigation_reply(session: dict, incident: dict, assessment: dict, focus: str, latest_text: str) -> str:
    root = assessment.get("root_cause_analysis", {})
    confidence = int(root.get("confidence", 0) or 0)
    notes = _session_notes(session)
    header = "🧭 <b>RCA Investigation</b>"
    lines = [
        header,
        f"Incident: <code>{_html(session['incident_id'])}</code> · cập nhật #{len(session['messages'])}",
        f"Ghi nhận mới: {_html(_short_text(latest_text, 180))}",
    ]
    if notes:
        lines.extend(["", "<b>Context đang có</b>"])
        lines.extend(f"• {_html(note)}" for note in notes)

    lines.extend(["", "<b>Nhận định hiện tại</b>"])
    lines.extend(_format_rca_section(assessment))

    if focus == "change":
        lines.extend(["", "<b>Change/config rà soát được</b>"])
        lines.extend(_format_change_section(incident))
    elif focus == "timeline":
        lines.extend(["", "<b>Timeline/log đáng chú ý</b>"])
        lines.extend(_format_timeline_section(assessment, limit=10))
    elif focus == "action":
        lines.extend(["", "<b>Hành động đề xuất</b>"])
        lines.extend(_format_action_section(assessment))
    else:
        lines.extend(["", "<b>Timeline/log đáng chú ý</b>"])
        lines.extend(_format_timeline_section(assessment, limit=5))
        lines.extend(["", "<b>Hành động tiếp theo</b>"])
        lines.extend(_format_action_section(assessment)[:3])

    if root.get("needs_more_evidence") or confidence < 70:
        lines.extend(
            [
                "",
                "<b>Cần bổ sung để kết luận chắc hơn</b>",
                "• Log raw quanh incident window",
                "• Metric liên quan CPU/memory/disk/session/latency/packet loss",
                "• Change history hoặc ticket gần thời điểm lỗi",
                "• Phạm vi impact: user/service/site/device nào bị ảnh hưởng",
            ]
        )

    text = "\n".join(lines)
    if len(text) > 3800:
        return text[:3790].rstrip() + "\n..."
    return text


def _analyze_investigation_session(session: dict, latest_text: str, focus: str) -> dict:
    built = _build_session_incident(session)
    incident = built["incident"]
    assessment = analyze_incident(incident, send_telegram=False)
    session["last_incident"] = incident
    session["last_assessment"] = assessment
    session["last_intake"] = built["intake"]
    reply = _format_investigation_reply(session, incident, assessment, focus, latest_text)
    return {"incident": incident, "assessment": assessment, "intake": built["intake"], "reply": reply}


def _telegram_message(payload: dict) -> tuple[str | int | None, str, dict]:
    message = None
    for key in ("message", "edited_message", "channel_post"):
        value = payload.get(key)
        if isinstance(value, dict):
            message = value
            break
    if message is None and isinstance(payload.get("callback_query"), dict):
        message = payload["callback_query"].get("message") or {}
        if not message.get("text"):
            message = dict(message)
            message["text"] = payload["callback_query"].get("data", "")

    if not isinstance(message, dict):
        return None, "", {}

    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    text = str(message.get("text") or message.get("caption") or "").strip()
    return chat_id, text, message


def _is_help_text(text: str) -> bool:
    normalized = normalize_text(text)
    return normalized in {"/start", "start", "/help", "help", "tro giup", "huong dan"}


def _help_reply() -> str:
    return "\n".join(
        [
            "🤖 <b>AIOps RCA Agent</b>",
            "",
            "Bạn có thể mở một investigation bằng mô tả tự nhiên:",
            "• internet chậm từ 09:30-10:00, user chi nhánh HCM bị ảnh hưởng",
            "• mất kết nối server DB-01, nghi service crash sau deploy",
            "• port ge-0/0/1 flap nhiều lần, có CRC error trong log",
            "",
            "Sau đó cứ gửi thêm log, metric, impact, đối tượng nghi ngờ, giả định của bạn hoặc hỏi:",
            "• timeline/log đáng chú ý là gì",
            "• có change cấu hình trong khoảng 09:30-10:00 không",
            "• root cause hiện tại và bằng chứng là gì",
            "• nên xử lý bước nào trước",
            "",
            "Dùng /new để bắt đầu sự cố mới, /close để đóng investigation hiện tại.",
        ]
    )


def _is_random_demo_request(text: str) -> bool:
    normalized = normalize_text(text)
    if any(term in normalized for term in ("ngau nhien", "random", "bat ky")):
        return True

    create_terms = ("tao incident", "tao su co", "sinh incident", "sinh su co", "tao alert", "demo alert")
    if any(term in normalized for term in create_terms):
        match = match_report_template(text)
        return int(match.get("score", 0)) <= 0
    return False


def _handle_telegram_chat(text: str, chat_id: str | int | None = None) -> dict:
    if not text:
        reply = _help_reply()
        delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {"status": "success", "workflow": "telegram_chat", "intent": "help", "reply": reply, "telegram_delivery": delivery}

    if _is_help_text(text):
        reply = _help_reply()
        delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {"status": "success", "workflow": "telegram_chat", "intent": "help", "reply": reply, "telegram_delivery": delivery}

    if _is_random_demo_request(text):
        result = _alert_from_generated(
            {"incident_type": "random", "send_telegram": False},
            default_prefix="INC-TELEGRAM-DEMO",
        )
        result["workflow"] = "telegram_chat"
        result["intent"] = "proactive_alert"
        result["chat_text"] = text
        delivery = send_telegram_report(result["assessment"]["telegram_report"], chat_id=chat_id) if chat_id is not None else {"sent": False}
        result["telegram_delivery"] = delivery
        return result

    key = _chat_key(chat_id)
    if _is_close_investigation_command(text):
        if key:
            INVESTIGATION_SESSIONS.pop(key, None)
        reply = "✅ <b>Đã đóng investigation hiện tại.</b>\nGửi mô tả sự cố mới khi bạn muốn bắt đầu phân tích tiếp."
        delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {"status": "success", "workflow": "telegram_chat", "intent": "close_investigation", "reply": reply, "telegram_delivery": delivery}

    if key and key in INVESTIGATION_SESSIONS and not _is_new_investigation_command(text):
        session = INVESTIGATION_SESSIONS[key]
        _append_session_message(session, text)
        focus = _detect_focus(text)
        result = _analyze_investigation_session(session, latest_text=text, focus=focus)
        delivery = send_telegram_report(result["reply"], chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {
            "status": "success",
            "workflow": "telegram_chat",
            "intent": "continue_investigation",
            "chat_text": text,
            "session": {
                "incident_id": session["incident_id"],
                "message_count": len(session["messages"]),
                "time_windows": session["time_windows"],
                "entities": session["entities"],
            },
            "intake": result["intake"],
            "incident": result["incident"],
            "assessment": result["assessment"],
            "reply": result["reply"],
            "telegram_delivery": delivery,
        }

    initial_text = _start_new_investigation_text(text) if _is_new_investigation_command(text) else text
    session = _create_investigation_session(chat_id, initial_text)
    result = _analyze_investigation_session(session, latest_text=initial_text, focus=_detect_focus(initial_text))
    incident = result["incident"]
    assessment = result["assessment"]
    delivery = send_telegram_report(result["reply"], chat_id=chat_id) if chat_id is not None else {"sent": False}
    return {
        "status": "success",
        "workflow": "telegram_chat",
        "intent": "start_investigation",
        "chat_text": text,
        "session": {
            "incident_id": session["incident_id"],
            "message_count": len(session["messages"]),
            "time_windows": session["time_windows"],
            "entities": session["entities"],
        },
        "intake": result["intake"],
        "incident": incident,
        "assessment": assessment,
        "reply": result["reply"],
        "telegram_delivery": delivery,
    }


def _alert_from_generated(payload: dict, default_prefix: str) -> dict:
    generated = _generate_from_payload(payload, default_prefix=default_prefix)
    if generated.get("status") != "success":
        return generated
    incident = generated["incident"]
    assessment = analyze_incident(
        incident,
        send_telegram=_as_bool(payload.get("send_telegram"), default=True),
    )
    return {
        "status": "success",
        "workflow": "proactive_alert",
        "incident_type": generated["incident_type"],
        "seed": generated["seed"],
        "incident": incident,
        "assessment": assessment,
        "reply": _analyst_reply(incident, assessment),
    }


@app.entrypoint
def handler(payload: dict, context: RequestContext) -> dict:
    """Handle AgentBase POST /invocations requests.

    Supported operations:
    - analyze: analyze a provided incident JSON.
    - generate: generate one synthetic incident.
    - proactive_alert: generate/analyze/notify a synthetic incident.
    - record_incident: normalize a user report, analyze it, and respond.
    - telegram_chat: handle Telegram-style chat text or webhook updates.
    - evaluate: generate/evaluate a synthetic dataset, or evaluate provided incidents.
    """

    if "operation" not in payload:
        chat_id, text, message = _telegram_message(payload)
        if message:
            return _handle_telegram_chat(text, chat_id=chat_id)

    operation = payload.get("operation", "analyze")

    if operation == "generate":
        return _generate_from_payload(payload)

    if operation == "demo_alert":
        return _alert_from_generated(payload, default_prefix="INC-DEMO-ALERT")

    if operation in {"proactive_alert", "proactive_check"}:
        return _alert_from_generated(payload, default_prefix="INC-PROACTIVE")

    if operation == "evaluate":
        incidents = payload.get("incidents")
        if incidents is None:
            incidents = generate_dataset(
                per_category=int(payload.get("per_category", 20)),
                seed=int(payload.get("seed", 42)),
            )
        return {"status": "success", "evaluation": evaluate_incidents(incidents)}

    if operation == "analyze":
        incident = payload.get("incident")
        if incident is None:
            return {"status": "error", "message": "Missing required field: incident"}
        return {
            "status": "success",
            "assessment": analyze_incident(
                incident,
                send_telegram=_as_bool(payload.get("send_telegram"), default=False),
            ),
        }

    if operation in {"record_incident", "submit_incident", "user_report", "triage_incident"}:
        try:
            normalized = build_incident_from_report(payload)
        except ValueError as exc:
            return {"status": "error", "message": str(exc)}

        incident = normalized["incident"]
        assessment = analyze_incident(
            incident,
            send_telegram=_as_bool(payload.get("send_telegram"), default=False),
        )
        return {
            "status": "success",
            "workflow": "record_incident",
            "intake": normalized["intake"],
            "incident": incident,
            "assessment": assessment,
            "reply": _analyst_reply(incident, assessment),
        }

    if operation in {"telegram_chat", "chat"}:
        chat_id = payload.get("chat_id")
        text = payload.get("text") or payload.get("message") or payload.get("description") or ""
        if isinstance(text, dict):
            chat_id, text, _ = _telegram_message(payload)
        return _handle_telegram_chat(str(text), chat_id=chat_id)

    return {"status": "error", "message": f"Unsupported operation: {operation}"}


@app.ping
def health_check() -> PingStatus:
    return PingStatus.HEALTHY


if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
