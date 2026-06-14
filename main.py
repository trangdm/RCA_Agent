"""AgentBase entrypoint for the AIOps Incident Investigation Agent."""

from __future__ import annotations

from datetime import datetime, timezone
import random
import sys

from dotenv import load_dotenv
from greennode_agentbase import GreenNodeAgentBaseApp, PingStatus, RequestContext

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_incident
from aiops_incident_agent.intake import build_incident_from_report, match_report_template, normalize_text
from aiops_incident_agent.catalog import TEMPLATES, TEMPLATES_BY_KEY, IncidentTemplate
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.telegram import (
    answer_callback_query,
    format_telegram_detail,
    send_telegram_report,
    telegram_action_keyboard,
)


load_dotenv()

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

app = GreenNodeAgentBaseApp()
RECENT_ASSESSMENTS: dict[str, dict] = {}
RECENT_ASSESSMENT_LIMIT = 100


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


def _cache_assessment(assessment: dict) -> None:
    incident_id = assessment.get("incident_id")
    if not incident_id:
        return
    RECENT_ASSESSMENTS[str(incident_id)] = assessment
    while len(RECENT_ASSESSMENTS) > RECENT_ASSESSMENT_LIMIT:
        oldest_key = next(iter(RECENT_ASSESSMENTS))
        RECENT_ASSESSMENTS.pop(oldest_key, None)


def _send_assessment(chat_id: str | int | None, assessment: dict) -> dict:
    _cache_assessment(assessment)
    return send_telegram_report(
        assessment["telegram_report"],
        chat_id=chat_id,
        reply_markup=telegram_action_keyboard(assessment.get("incident_id")),
    )


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


def _handle_telegram_callback(callback_query: dict) -> dict:
    callback_id = callback_query.get("id")
    data = str(callback_query.get("data") or "")
    message = callback_query.get("message") or {}
    chat_id = (message.get("chat") or {}).get("id")

    if not data.startswith("rca:"):
        ack = answer_callback_query(callback_id, "Unknown action")
        return {"status": "success", "workflow": "telegram_callback", "telegram_ack": ack}

    _, section, incident_id = data.split(":", 2)
    assessment = RECENT_ASSESSMENTS.get(incident_id)
    if not assessment:
        text = (
            "⚠️ <b>Details expired</b>\n"
            "Cache chi tiết của incident này không còn trong runtime. "
            "Hãy gửi lại câu hỏi hoặc tạo incident demo mới."
        )
        delivery = send_telegram_report(text, chat_id=chat_id)
        ack = answer_callback_query(callback_id, "Details expired")
        return {
            "status": "success",
            "workflow": "telegram_callback",
            "incident_id": incident_id,
            "telegram_delivery": delivery,
            "telegram_ack": ack,
        }

    detail_text = format_telegram_detail(assessment, section)
    delivery = send_telegram_report(detail_text, chat_id=chat_id)
    ack = answer_callback_query(callback_id, "Sent details")
    return {
        "status": "success",
        "workflow": "telegram_callback",
        "incident_id": incident_id,
        "section": section,
        "telegram_delivery": delivery,
        "telegram_ack": ack,
    }


def _is_help_text(text: str) -> bool:
    normalized = normalize_text(text)
    return normalized in {"/start", "start", "/help", "help", "tro giup", "huong dan"}


def _help_reply() -> str:
    return "\n".join(
        [
            "🤖 <b>AIOps RCA Agent</b>",
            "",
            "Bạn có thể chat tự nhiên, ví dụ:",
            "• tạo ra incident ngẫu nhiên",
            "• internet chậm kết nối hãy kiểm tra có gì bất thường không",
            "• mất kết nối server DB-01 có gì bất thường không",
            "• port ge-0/0/1 bị flap nhiều lần có ghi nhận gì bất thường không",
            "",
            "Agent sẽ tạo incident demo liên quan, phân tích RCA và gửi alert tại đây.",
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
        delivery = _send_assessment(chat_id, result["assessment"]) if chat_id is not None else {"sent": False}
        result["telegram_delivery"] = delivery
        return result

    normalized = build_incident_from_report(
        {
            "message": text,
            "source": "telegram-chat",
            "send_telegram": False,
        }
    )
    incident = normalized["incident"]
    assessment = analyze_incident(incident, send_telegram=False)
    delivery = _send_assessment(chat_id, assessment) if chat_id is not None else {"sent": False}
    return {
        "status": "success",
        "workflow": "telegram_chat",
        "intent": "record_incident",
        "chat_text": text,
        "intake": normalized["intake"],
        "incident": incident,
        "assessment": assessment,
        "reply": _analyst_reply(incident, assessment),
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
        if isinstance(payload.get("callback_query"), dict):
            return _handle_telegram_callback(payload["callback_query"])
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
