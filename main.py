"""AgentBase entrypoint for the AIOps RCA Agent."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape, unescape
import os
import random
import re
import sys
from typing import Any

from dotenv import load_dotenv
from greennode_agentbase import GreenNodeAgentBaseApp, PingStatus, RequestContext
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from aiops_incident_agent.catalog import TEMPLATES, TEMPLATES_BY_KEY, IncidentTemplate
from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_incident, generate_required_scenarios
from aiops_incident_agent.intake import build_incident_from_report, match_report_template, normalize_text
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.store import latest_assessment
from aiops_incident_agent.telegram import send_telegram_report


load_dotenv()

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")


app = GreenNodeAgentBaseApp()
_cors_origins = [
    origin.strip()
    for origin in os.getenv("AIOPS_CHAT_CORS_ORIGINS", "").split(",")
    if origin.strip() and origin.strip() != "*"
]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
INVESTIGATION_SESSIONS: dict[str, dict[str, Any]] = {}
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


def _html(value: object, default: str = "unknown", limit: int | None = None) -> str:
    text = str(value if value not in {None, ""} else default)
    text = " ".join(text.split())
    if limit is not None and len(text) > limit:
        text = text[: max(0, limit - 3)].rstrip() + "..."
    return escape(text, quote=False)


def _short_time(value: object) -> str:
    if not value:
        return "unknown"
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(timezone.utc)
        return parsed.strftime("%H:%M:%S UTC")
    except ValueError:
        return str(value)


def _chat_key(chat_id: str | int | None) -> str | None:
    if chat_id is None:
        return None
    return str(chat_id)


def _template_from_payload(payload: dict[str, Any]) -> tuple[IncidentTemplate | None, str | None]:
    incident_type = str(payload.get("incident_type", "random")).strip().lower()
    if incident_type in {"", "random", "any"}:
        rng = random.Random(int(payload["seed"])) if payload.get("seed") is not None else random.SystemRandom()
        return rng.choice(TEMPLATES), None
    template = TEMPLATES_BY_KEY.get(incident_type)
    if template is not None:
        return template, None
    match = match_report_template(incident_type)
    if int(match.get("score", 0)) > 0:
        return match["template"], None
    return None, f"Unknown incident_type: {incident_type}"


def _generate_from_payload(payload: dict[str, Any], default_prefix: str = "INC-DEMO") -> dict[str, Any]:
    if payload.get("all_required_scenarios"):
        return {
            "status": "success",
            "incidents": generate_required_scenarios(seed=int(payload.get("seed", 42))),
        }

    template, error = _template_from_payload(payload)
    if error or template is None:
        return {"status": "error", "message": error}

    seed = int(payload["seed"]) if payload.get("seed") is not None else random.SystemRandom().randint(1, 10_000_000)
    incident = generate_incident(
        incident_id=payload.get("incident_id") or _new_incident_id(default_prefix),
        template=template,
        seed=seed,
    )
    return {
        "status": "success",
        "incident_type": template.key,
        "seed": seed,
        "incident": incident,
    }


def _alert_from_generated(payload: dict[str, Any], default_prefix: str) -> dict[str, Any]:
    generated = _generate_from_payload(payload, default_prefix=default_prefix)
    if generated.get("status") != "success":
        return generated
    incident = generated["incident"]
    assessment = analyze_incident(
        incident,
        send_telegram=_as_bool(payload.get("send_telegram"), default=True),
        chat_id=payload.get("chat_id"),
    )
    return {
        "status": "success",
        "workflow": "proactive_alert",
        "incident_type": generated["incident_type"],
        "seed": generated["seed"],
        "incident": incident,
        "assessment": assessment,
        "reply": _brief_reply(assessment),
    }


def _brief_reply(assessment: dict[str, Any]) -> str:
    return (
        f"Đã phân tích <code>{_html(assessment.get('incident_id'))}</code>. "
        f"Root cause khả năng cao nhất: <code>{_html(assessment.get('most_likely_root_cause'))}</code> "
        f"(<b>{int(assessment.get('confidence') or 0)}%</b>). "
        f"Trạng thái: <code>{_html(assessment.get('status'))}</code>."
    )


def _telegram_message(payload: dict[str, Any]) -> tuple[str | int | None, str, dict[str, Any]]:
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
    return chat.get("id"), str(message.get("text") or message.get("caption") or "").strip(), message


def _is_help_text(text: str) -> bool:
    normalized = normalize_text(text)
    return normalized in {"/start", "start", "/help", "help", "tro giup", "huong dan"}


def _help_reply() -> str:
    return "\n".join(
        [
            "🤖 <b>AIOps RCA Agent</b>",
            "",
            "Bạn có thể mô tả sự cố tự nhiên, ví dụ:",
            "- internet chậm từ 09:30-10:00, packet loss cao",
            "- camera 01 down, nghi port switch bị down",
            "- mất kết nối server DB-01 sau deploy",
            "- port ge-0/0/1 flap nhiều lần",
            "",
            "Mình sẽ dựng incident demo liên quan, rà log/metric/topology/change synthetic, xâu chuỗi timeline, rồi trả RCA.",
            "Hỏi tiếp bất kỳ ý nào bạn cần: change trong khoảng thời gian, evidence, timeline, hypothesis, hoặc runbook/check.",
            "",
            "Dùng /new để bắt đầu sự cố mới, /close để đóng context hiện tại.",
        ]
    )


def _is_random_demo_request(text: str) -> bool:
    normalized = normalize_text(text)
    return any(term in normalized for term in ("ngau nhien", "random", "bat ky", "demo alert", "tao incident random"))


def _is_new_command(text: str) -> bool:
    normalized = normalize_text(text)
    return normalized.startswith(("/new", "new incident", "incident moi", "su co moi", "bat dau su co moi"))


def _is_close_command(text: str) -> bool:
    normalized = normalize_text(text)
    return normalized in {"/close", "/done", "dong su co", "ket thuc su co", "reset", "/reset"}


def _extract_time_window(text: str) -> str | None:
    matches = re.findall(r"\b(\d{1,2})\s*(?::|h)\s*(\d{2})\b", normalize_text(text))
    if len(matches) < 2:
        return None
    start_hour, start_minute = (int(part) for part in matches[0])
    end_hour, end_minute = (int(part) for part in matches[1])
    if not (0 <= start_hour <= 23 and 0 <= end_hour <= 23 and 0 <= start_minute <= 59 and 0 <= end_minute <= 59):
        return None
    return f"{start_hour:02d}:{start_minute:02d}-{end_hour:02d}:{end_minute:02d}"


def _extract_entities(text: str) -> list[str]:
    patterns = [
        r"\b[A-Za-z]{2,}[-_][A-Za-z0-9_-]+\b",
        r"\b(?:ge|gi|xe|et)-?\d+/\d+/\d+\b",
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
        r"\bcamera\s*\d+\b",
    ]
    entities: list[str] = []
    for pattern in patterns:
        entities.extend(re.findall(pattern, text, flags=re.IGNORECASE))
    return sorted(set(entities), key=lambda item: item.lower())[:10]


def _detect_focus(text: str) -> str:
    normalized = normalize_text(text)
    if any(term in normalized for term in ("command", "cmd", "runbook", "check", "kiem tra", "verify", "action")):
        return "runbook"
    if any(term in normalized for term in ("change", "config", "cau hinh", "audit", "ai thuc hien")):
        return "change"
    if any(term in normalized for term in ("timeline", "log", "event", "su kien")):
        return "timeline"
    if any(term in normalized for term in ("root cause", "rca", "nguyen nhan", "hypothesis", "evidence", "bang chung")):
        return "rca"
    return "update"


def _session_for_message(chat_id: str | int | None, text: str) -> dict[str, Any]:
    key = _chat_key(chat_id)
    if key and key in INVESTIGATION_SESSIONS and not _is_new_command(text):
        session = INVESTIGATION_SESSIONS[key]
    else:
        session = {
            "chat_id": key,
            "incident_id": _new_incident_id("INC-INV"),
            "seed": random.SystemRandom().randint(1, 10_000_000),
            "created_at": _iso_now(),
            "messages": [],
            "time_windows": [],
            "entities": [],
        }
        if key:
            INVESTIGATION_SESSIONS[key] = session
            while len(INVESTIGATION_SESSIONS) > INVESTIGATION_SESSION_LIMIT:
                INVESTIGATION_SESSIONS.pop(next(iter(INVESTIGATION_SESSIONS)), None)

    cleaned = re.sub(r"^\s*/new\s*", "", text, flags=re.IGNORECASE).strip() or text
    session["messages"].append({"timestamp": _iso_now(), "text": cleaned})
    session["updated_at"] = _iso_now()
    window = _extract_time_window(cleaned)
    if window and window not in session["time_windows"]:
        session["time_windows"].append(window)
    for entity in _extract_entities(cleaned):
        if entity not in session["entities"]:
            session["entities"].append(entity)
    return session


def _build_session_incident(session: dict[str, Any]) -> dict[str, Any]:
    combined = "\n".join(item["text"] for item in session["messages"])
    normalized = build_incident_from_report(
        {
            "message": combined,
            "source": "telegram-chat",
            "incident_id": session["incident_id"],
            "seed": session["seed"],
        }
    )
    incident = normalized["incident"]
    incident.setdefault("investigation_context", {})
    incident["investigation_context"] = {
        "message_count": len(session["messages"]),
        "time_windows": list(session["time_windows"]),
        "entities": list(session["entities"]),
    }
    for index, message in enumerate(session["messages"], start=1):
        incident["logs"].append(
            {
                "timestamp": message["timestamp"],
                "source": "operator",
                "event_type": "operator_observation",
                "severity": "info",
                "message": f"Observation {index}: {message['text'][:240]}",
                "role": "evidence",
                "signal": "related",
            }
        )
    incident["logs"] = sorted(incident["logs"], key=lambda item: item.get("timestamp", ""))
    return {"incident": incident, "intake": normalized["intake"]}


def _timeline_reply(assessment: dict[str, Any], limit: int = 7) -> list[str]:
    timeline = [event for event in assessment.get("timeline", []) if event.get("signal") not in {"noise", "baseline"}]
    if not timeline:
        return ["- Chưa có timeline event đủ tin cậy."]
    lines = []
    for event in timeline[:limit]:
        lines.append(
            f"- <code>{_html(_short_time(event.get('time')))}</code> "
            f"[{_html(event.get('type'))}] <code>{_html(event.get('source'))}</code>: "
            f"{_html(event.get('event'), limit=150)}"
        )
    return lines


def _change_reply(incident: dict[str, Any]) -> list[str]:
    changes = incident.get("recent_changes") or incident.get("change_history") or []
    if not changes:
        return ["- Chưa thấy change/config event trong dữ liệu hiện có."]
    return [
        f"- <code>{_html(_short_time(change.get('time') or change.get('timestamp')))}</code> "
        f"<code>{_html(change.get('device'))}</code>: {_html(change.get('action'), limit=180)}"
        for change in changes[:8]
    ]


def _runbook_commands(root_cause: str) -> list[str]:
    commands = {
        "Broadcast Loop on Aruba switch": [
            "show spanning-tree vlan <vlan>",
            "show mac-address-table move",
            "show interface 1/1/48 counters",
            "show running-config interface 1/1/48",
        ],
        "MAC flapping on core switch": [
            "show ethernet-switching table | match <mac>",
            "show lacp interfaces ae1",
            "show log messages | match MAC",
        ],
        "Fortigate session spike causing high CPU": [
            "diagnose sys session stat",
            "diagnose sys top 5 20",
            "diagnose sys session list | head",
            "show firewall policy",
        ],
        "DNS server timeout": [
            "dig @<dns_server> <record>",
            "dig +trace <record>",
            "ping <upstream_dns>",
            "journalctl -u named --since '<incident_start>'",
        ],
        "Linux server disk full": [
            "df -h",
            "du -xhd1 /var | sort -h",
            "journalctl --disk-usage",
            "lsof +L1",
        ],
        "Windows service crash": [
            "Get-Service <service>",
            "Get-EventLog -LogName Application -Newest 100",
            "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime='<incident_start>'}",
        ],
        "VMware datastore full": [
            "vim-cmd hostsvc/datastore/listsummary",
            "vim-cmd vmsvc/snapshot.get <vmid>",
            "esxcli storage filesystem list",
        ],
        "Interface flapping": [
            "show interfaces ge-0/0/1 terse",
            "show interfaces ge-0/0/1 extensive",
            "show log messages | match ge-0/0/1",
            "show lacp interfaces ge-0/0/1",
        ],
        "Routing issue": [
            "show route <prefix>",
            "show bgp summary",
            "show route advertising-protocol bgp <peer>",
            "show configuration policy-options",
        ],
        "Brute force attack detected by Wazuh": [
            "grep -i 'failed password' /var/log/auth.log | tail -100",
            "show vpn ssl monitor",
            "show log auth | tail",
            "wazuh-logtest",
        ],
    }
    return commands.get(
        root_cause,
        [
            "show logs around <incident_start>-<incident_end>",
            "show recent changes or config audit",
            "show health/status for <suspected_object>",
            "show metrics for affected node",
        ],
    )


def _format_chat_reply(session: dict[str, Any], incident: dict[str, Any], assessment: dict[str, Any], focus: str) -> str:
    first_turn = len(session["messages"]) == 1
    root = assessment.get("most_likely_root_cause", "Undetermined")
    confidence = int(assessment.get("confidence") or 0)
    status = assessment.get("status")

    if first_turn:
        opening = (
            f"Ok, mình đã tạo incident demo <code>{_html(session['incident_id'])}</code> từ mô tả của bạn "
            "và rà synthetic log/metric/topology/change liên quan."
        )
    else:
        opening = (
            f"Mình đã thêm thông tin mới vào incident <code>{_html(session['incident_id'])}</code> "
            "và chạy lại RCA theo toàn bộ context hiện có."
        )

    if root == "Undetermined" or confidence < 70:
        verdict = (
            f"Hiện chưa đủ dữ liệu để chốt root cause. Candidate mạnh nhất đang ở mức <b>{confidence}%</b>, "
            "nên mình giữ trạng thái <code>insufficient_data</code>."
        )
    else:
        verdict = (
            f"Root cause khả năng cao nhất là <code>{_html(root)}</code> với độ tin cậy <b>{confidence}%</b>. "
            f"Trạng thái: <code>{_html(status)}</code>."
        )

    lines = [opening, "", verdict, "", "<b>Evidence chính:</b>"]
    evidence = assessment.get("evidence") or []
    if evidence:
        lines.extend(f"- {_html(item, limit=180)}" for item in evidence[:5])
    else:
        lines.append("- Chưa có evidence đủ mạnh trong payload.")

    if session.get("time_windows") or session.get("entities"):
        lines.append("")
        lines.append("<b>Context mình đang giữ:</b>")
        if session.get("time_windows"):
            lines.append(f"- Time window: {_html(', '.join(session['time_windows']))}")
        if session.get("entities"):
            lines.append(f"- Object nghi ngờ: {_html(', '.join(session['entities']))}")

    if focus == "change":
        lines.extend(["", "<b>Change/config trong dữ liệu:</b>"])
        lines.extend(_change_reply(incident))
    elif focus == "timeline":
        lines.extend(["", "<b>Timeline đáng chú ý:</b>"])
        lines.extend(_timeline_reply(assessment, limit=10))
    elif focus == "rca":
        lines.extend(["", "<b>Root cause candidates:</b>"])
        for item in assessment.get("root_cause_hypotheses", [])[:5]:
            lines.append(f"- {_html(item.get('hypothesis'))}: <b>{int(item.get('confidence') or 0)}%</b>")
    elif focus == "runbook":
        lines.extend(["", "<b>Runbook/check an toàn:</b>"])
        for command in _runbook_commands(str(root))[:8]:
            lines.append(f"- <code>{_html(command)}</code>")
    else:
        lines.extend(["", "<b>Timeline ngắn:</b>"])
        lines.extend(_timeline_reply(assessment, limit=5))
        lines.extend(["", "<b>Bước nên làm ngay:</b>"])
        actions = assessment.get("recommended_actions", {}).get("immediate_actions", [])
        lines.extend(f"{index}. {_html(action, limit=160)}" for index, action in enumerate(actions[:3], start=1))

    text = "\n".join(lines)
    if len(text) > 3900:
        return text[:3890].rstrip() + "\n..."
    return text


def _new_web_session_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = random.SystemRandom().randint(1000, 9999)
    return f"web-{timestamp}-{suffix}"


def _web_session_key(session_id: str) -> str:
    return f"web:{session_id}"


def _strip_html(value: object) -> str:
    text = str(value or "")
    text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"</p\s*>", "\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    return unescape(text).strip()


def _compact_timeline(assessment: dict[str, Any], limit: int = 8) -> list[dict[str, Any]]:
    events = [event for event in assessment.get("timeline", []) if event.get("signal") not in {"noise", "baseline"}]
    if not events:
        events = list(assessment.get("timeline", []))
    return [
        {
            "time": event.get("time"),
            "type": event.get("type"),
            "source": event.get("source"),
            "event": event.get("event"),
            "severity": event.get("severity"),
        }
        for event in events[:limit]
    ]


def _web_chat_response(
    session_id: str,
    result: dict[str, Any],
    include_assessment: bool = False,
) -> dict[str, Any]:
    assessment = result.get("assessment") or {}
    session = result.get("session") or {}
    reply_html = result.get("reply") or assessment.get("telegram_report") or ""
    response: dict[str, Any] = {
        "status": result.get("status", "success"),
        "workflow": "web_chat",
        "intent": result.get("intent"),
        "session_id": session_id,
        "incident_id": assessment.get("incident_id") or session.get("incident_id"),
        "reply_html": reply_html,
        "reply_text": _strip_html(reply_html),
        "root_cause": assessment.get("most_likely_root_cause"),
        "confidence": assessment.get("confidence"),
        "rca_status": assessment.get("status"),
        "summary": assessment.get("summary"),
        "impact": assessment.get("impact"),
        "evidence": assessment.get("evidence", []),
        "timeline": _compact_timeline(assessment),
        "recommended_actions": assessment.get("recommended_actions", {}),
        "missing_data": assessment.get("missing_data", []),
        "session": session,
        "intake": result.get("intake", {}),
    }
    if include_assessment:
        response["assessment"] = assessment
        if "incident" in result:
            response["incident"] = result["incident"]
    return response


def _handle_web_chat(payload: dict[str, Any]) -> dict[str, Any]:
    """Handle web chat requests without sending Telegram messages."""

    text = str(payload.get("message") or payload.get("text") or "").strip()
    session_id = str(payload.get("session_id") or _new_web_session_id()).strip()
    if not session_id:
        session_id = _new_web_session_id()
    key = _web_session_key(session_id)
    include_assessment = _as_bool(payload.get("include_assessment"), default=False)

    if not text or _is_help_text(text):
        reply = _help_reply()
        return _web_chat_response(
            session_id,
            {
                "status": "success",
                "intent": "help",
                "reply": reply,
                "session": {"session_id": session_id, "message_count": 0},
            },
            include_assessment=include_assessment,
        )

    if _is_close_command(text):
        INVESTIGATION_SESSIONS.pop(key, None)
        reply = "✅ <b>Đã đóng web chat session.</b>\nGửi mô tả mới để bắt đầu RCA tiếp."
        return _web_chat_response(
            session_id,
            {
                "status": "success",
                "intent": "close_investigation",
                "reply": reply,
                "session": {"session_id": session_id, "message_count": 0},
            },
            include_assessment=include_assessment,
        )

    if _is_random_demo_request(text):
        result = _alert_from_generated(
            {"incident_type": "random", "send_telegram": False},
            default_prefix="INC-WEB-DEMO",
        )
        result["intent"] = "proactive_alert"
        result["reply"] = result.get("reply") or (result.get("assessment") or {}).get("telegram_report", "")
        result["session"] = {"session_id": session_id, "message_count": 0}
        return _web_chat_response(session_id, result, include_assessment=include_assessment)

    session = _session_for_message(key, text)
    built = _build_session_incident(session)
    incident = built["incident"]
    assessment = analyze_incident(incident, send_telegram=False)
    session["last_incident"] = incident
    session["last_assessment"] = assessment
    focus = _detect_focus(text)
    reply = _format_chat_reply(session, incident, assessment, focus)
    result = {
        "status": "success",
        "intent": "start_investigation" if len(session["messages"]) == 1 else "continue_investigation",
        "session": {
            "session_id": session_id,
            "incident_id": session["incident_id"],
            "message_count": len(session["messages"]),
            "time_windows": session["time_windows"],
            "entities": session["entities"],
        },
        "intake": built["intake"],
        "incident": incident,
        "assessment": assessment,
        "reply": reply,
    }
    return _web_chat_response(session_id, result, include_assessment=include_assessment)


async def web_chat_endpoint(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON body"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"status": "error", "message": "JSON body must be an object"}, status_code=400)
    return JSONResponse(_handle_web_chat(payload))


async def web_chat_session_endpoint(request: Request) -> JSONResponse:
    session_id = request.path_params.get("session_id", "")
    key = _web_session_key(str(session_id))
    session = INVESTIGATION_SESSIONS.get(key)
    if not session:
        return JSONResponse({"status": "success", "found": False, "session_id": session_id})
    assessment = session.get("last_assessment") or {}
    return JSONResponse(
        {
            "status": "success",
            "found": True,
            "session_id": session_id,
            "session": {
                "incident_id": session.get("incident_id"),
                "message_count": len(session.get("messages", [])),
                "time_windows": session.get("time_windows", []),
                "entities": session.get("entities", []),
                "created_at": session.get("created_at"),
                "updated_at": session.get("updated_at"),
            },
            "root_cause": assessment.get("most_likely_root_cause"),
            "confidence": assessment.get("confidence"),
            "rca_status": assessment.get("status"),
        }
    )


app.add_route("/chat", web_chat_endpoint, methods=["POST"])
app.add_route("/chat/sessions/{session_id}", web_chat_session_endpoint, methods=["GET"])


def _handle_telegram_chat(text: str, chat_id: str | int | None = None) -> dict[str, Any]:
    if not text or _is_help_text(text):
        reply = _help_reply()
        delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {"status": "success", "workflow": "telegram_chat", "intent": "help", "reply": reply, "telegram_delivery": delivery}

    if _is_close_command(text):
        key = _chat_key(chat_id)
        if key:
            INVESTIGATION_SESSIONS.pop(key, None)
        reply = "✅ <b>Đã đóng investigation hiện tại.</b>\nGửi mô tả mới khi bạn muốn bắt đầu RCA tiếp."
        delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
        return {"status": "success", "workflow": "telegram_chat", "intent": "close_investigation", "reply": reply, "telegram_delivery": delivery}

    if _is_random_demo_request(text):
        result = _alert_from_generated(
            {"incident_type": "random", "send_telegram": False, "chat_id": chat_id},
            default_prefix="INC-TELEGRAM-DEMO",
        )
        result["workflow"] = "telegram_chat"
        result["intent"] = "proactive_alert"
        delivery = send_telegram_report(result["assessment"]["telegram_report"], chat_id=chat_id) if chat_id is not None else {"sent": False}
        result["telegram_delivery"] = delivery
        return result

    session = _session_for_message(chat_id, text)
    built = _build_session_incident(session)
    incident = built["incident"]
    assessment = analyze_incident(incident, send_telegram=False)
    session["last_incident"] = incident
    session["last_assessment"] = assessment
    focus = _detect_focus(text)
    reply = _format_chat_reply(session, incident, assessment, focus)
    delivery = send_telegram_report(reply, chat_id=chat_id) if chat_id is not None else {"sent": False}
    return {
        "status": "success",
        "workflow": "telegram_chat",
        "intent": "start_investigation" if len(session["messages"]) == 1 else "continue_investigation",
        "chat_text": text,
        "session": {
            "incident_id": session["incident_id"],
            "message_count": len(session["messages"]),
            "time_windows": session["time_windows"],
            "entities": session["entities"],
        },
        "intake": built["intake"],
        "incident": incident,
        "assessment": assessment,
        "reply": reply,
        "telegram_delivery": delivery,
    }


@app.entrypoint
def handler(payload: dict[str, Any], context: RequestContext | None) -> dict[str, Any]:
    """Handle AgentBase POST /invocations requests."""

    payload = payload or {}
    if "operation" not in payload:
        chat_id, text, message = _telegram_message(payload)
        if message:
            return _handle_telegram_chat(text, chat_id=chat_id)

    operation = str(payload.get("operation", "analyze")).lower()

    if operation in {"generate", "demo/incidents/generate", "incidents_generate"}:
        return _generate_from_payload(payload)

    if operation in {"demo_alert", "proactive_alert", "proactive_check"}:
        return _alert_from_generated(payload, default_prefix="INC-PROACTIVE")

    if operation in {"analyze", "incidents/analyze", "incidents_analyze"}:
        incident = payload.get("incident")
        if incident is None:
            return {"status": "error", "message": "Missing required field: incident"}
        return {
            "status": "success",
            "assessment": analyze_incident(
                incident,
                send_telegram=_as_bool(payload.get("send_telegram"), default=False),
                chat_id=payload.get("chat_id"),
            ),
        }

    if operation in {"latest", "incidents/latest", "incidents_latest"}:
        return {"status": "success", "latest": latest_assessment()}

    if operation in {"telegram_test", "telegram/test"}:
        text = payload.get("text") or "AIOps RCA Agent Telegram test message."
        return {"status": "success", "telegram_delivery": send_telegram_report(str(text), chat_id=payload.get("chat_id"))}

    if operation in {"record_incident", "submit_incident", "user_report", "triage_incident"}:
        try:
            normalized = build_incident_from_report(payload)
        except ValueError as exc:
            return {"status": "error", "message": str(exc)}
        incident = normalized["incident"]
        assessment = analyze_incident(
            incident,
            send_telegram=_as_bool(payload.get("send_telegram"), default=False),
            chat_id=payload.get("chat_id"),
        )
        return {
            "status": "success",
            "workflow": "record_incident",
            "intake": normalized["intake"],
            "incident": incident,
            "assessment": assessment,
            "reply": _brief_reply(assessment),
        }

    if operation in {"telegram_chat"}:
        chat_id = payload.get("chat_id")
        text = payload.get("text") or payload.get("message") or payload.get("description") or ""
        if isinstance(text, dict):
            chat_id, text, _ = _telegram_message(payload)
        return _handle_telegram_chat(str(text), chat_id=chat_id)

    if operation in {"web_chat", "web/chat", "chat_endpoint", "chat"}:
        return _handle_web_chat(payload)

    if operation == "evaluate":
        incidents = payload.get("incidents")
        if incidents is None:
            incidents = generate_dataset(per_category=int(payload.get("per_category", 20)), seed=int(payload.get("seed", 42)))
        return {"status": "success", "evaluation": evaluate_incidents(incidents)}

    if operation == "health":
        return {"status": "ok"}

    return {"status": "error", "message": f"Unsupported operation: {operation}"}


@app.ping
def health_check() -> PingStatus:
    return PingStatus.HEALTHY


if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
