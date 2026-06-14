"""AgentBase entrypoint for the AIOps Incident Investigation Agent."""

from __future__ import annotations

import sys

from dotenv import load_dotenv
from greennode_agentbase import GreenNodeAgentBaseApp, PingStatus, RequestContext

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_incident
from aiops_incident_agent.catalog import TEMPLATES_BY_KEY
from aiops_incident_agent.pipeline import analyze_incident


load_dotenv()

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

app = GreenNodeAgentBaseApp()


@app.entrypoint
def handler(payload: dict, context: RequestContext) -> dict:
    """Handle AgentBase POST /invocations requests.

    Supported operations:
    - analyze: analyze a provided incident JSON.
    - generate: generate one synthetic incident.
    - evaluate: generate/evaluate a synthetic dataset, or evaluate provided incidents.
    """

    operation = payload.get("operation", "analyze")

    if operation == "generate":
        incident_type = payload.get("incident_type", "broadcast-loop")
        template = TEMPLATES_BY_KEY.get(incident_type)
        if template is None:
            return {"status": "error", "message": f"Unknown incident_type: {incident_type}"}
        return {
            "status": "success",
            "incident": generate_incident(
                incident_id=payload.get("incident_id", "INC-DEMO"),
                template=template,
                seed=payload.get("seed", 42),
            ),
        }

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
                send_telegram=bool(payload.get("send_telegram", False)),
            ),
        }

    return {"status": "error", "message": f"Unsupported operation: {operation}"}


@app.ping
def health_check() -> PingStatus:
    return PingStatus.HEALTHY


if __name__ == "__main__":
    app.run(port=8080, host="0.0.0.0")
