"""AgentBase entrypoint for the AIOps Incident Investigation Agent."""

from __future__ import annotations

from datetime import datetime, timezone
import random
import sys

from dotenv import load_dotenv
from greennode_agentbase import GreenNodeAgentBaseApp, PingStatus, RequestContext

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_incident
from aiops_incident_agent.intake import build_incident_from_report
from aiops_incident_agent.catalog import TEMPLATES, TEMPLATES_BY_KEY, IncidentTemplate
from aiops_incident_agent.pipeline import analyze_incident


load_dotenv()

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

app = GreenNodeAgentBaseApp()


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
    - evaluate: generate/evaluate a synthetic dataset, or evaluate provided incidents.
    """

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

    return {"status": "error", "message": f"Unsupported operation: {operation}"}


@app.ping
def health_check() -> PingStatus:
    return PingStatus.HEALTHY


if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
