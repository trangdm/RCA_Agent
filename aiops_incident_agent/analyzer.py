"""Root-cause analysis for synthetic AIOps incidents."""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from .catalog import TEMPLATES


def _incident_text(incident: dict[str, Any], timeline: list[dict[str, Any]]) -> str:
    parts = [
        incident.get("title", ""),
        incident.get("alert", {}).get("message", ""),
        incident.get("category", ""),
    ]
    for event in timeline:
        parts.extend([event.get("event_type", ""), event.get("source", ""), event.get("message", "")])
    for metric in incident.get("metrics", []):
        parts.extend([metric.get("metric", ""), str(metric.get("value", "")), metric.get("source", "")])
    for change in incident.get("change_history", []):
        parts.extend([change.get("device", ""), change.get("action", "")])
    return " ".join(parts).lower()


def _score_templates(text: str) -> list[dict[str, Any]]:
    ranked = []
    for template in TEMPLATES:
        matched = []
        score = 0
        for term in template.signatures:
            normalized = term.lower().replace(" ", "_")
            loose = normalized.replace("_", " ")
            if normalized in text or loose in text:
                matched.append(term)
                score += 10
        if template.root_cause.lower() in text:
            score += 20
            matched.append(template.root_cause)
        if template.category in text:
            score += 2
        ranked.append(
            {
                "root_cause": template.root_cause,
                "category": template.category,
                "score": score,
                "evidence": sorted(set(matched)),
            }
        )
    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked


def heuristic_root_cause(incident: dict[str, Any], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    """Deterministic root-cause scoring used for offline operation."""

    text = _incident_text(incident, timeline)
    ranked = _score_templates(text)
    top = ranked[0]
    if top["score"] <= 0:
        return {
            "root_cause": "Undetermined",
            "confidence": 35,
            "method": "heuristic",
            "ranked_hypotheses": ranked[:5],
            "needs_more_evidence": True,
        }
    second = ranked[1] if len(ranked) > 1 else {"score": 0}
    margin = max(0, top["score"] - second["score"])
    confidence = min(95, max(45, 55 + margin * 2 + min(top["score"], 50) // 2))
    return {
        "root_cause": top["root_cause"],
        "confidence": confidence,
        "method": "heuristic",
        "ranked_hypotheses": ranked[:5],
    }


def _with_hypothesis_probabilities(result: dict[str, Any]) -> dict[str, Any]:
    """Add a compact probability view for operator-facing summaries."""

    ranked = list(result.get("ranked_hypotheses") or [])[:5]
    root_cause = result.get("root_cause", "Unknown")
    try:
        confidence = int(result.get("confidence", 0))
    except (TypeError, ValueError):
        confidence = 0
    confidence = max(0, min(99, confidence))

    if root_cause == "Mistaken Camera Access Port Shutdown":
        root_evidence = []
        for item in ranked:
            if item.get("root_cause") == root_cause:
                evidence = item.get("evidence", [])
                priority = [
                    "config_port_shutdown",
                    "port_shutdown",
                    "admin_down",
                    "link_down",
                    "poe_power_lost",
                    "camera_heartbeat_lost",
                    "ge-0/0/1",
                ]
                root_evidence = [term for term in priority if term in evidence][:3]
                break
        remaining = max(0, 100 - confidence)
        poe_probability = max(1, round(remaining * 0.45)) if remaining else 0
        vms_probability = max(1, round(remaining * 0.30)) if remaining > 1 else 0
        camera_probability = max(0, remaining - poe_probability - vms_probability)
        result = dict(result)
        result["hypothesis_summary"] = [
            {
                "root_cause": root_cause,
                "probability": confidence,
                "evidence": root_evidence or ["config_port_shutdown", "link_down", "poe_power_lost"],
            },
            {
                "root_cause": "PoE or Physical Camera Link Failure",
                "probability": poe_probability,
                "evidence": ["poe_power_lost", "link_down", "crc_error_rate"],
            },
            {
                "root_cause": "VMS/NVR Path or Stream Issue",
                "probability": vms_probability,
                "evidence": ["rtsp_session_timeout", "camera_heartbeat_lost"],
            },
            {
                "root_cause": "Camera Endpoint Failure",
                "probability": camera_probability,
                "evidence": ["camera_heartbeat_lost"],
            },
        ]
        return result

    summary = []
    root_present = False
    for item in ranked:
        if item.get("root_cause") == root_cause:
            root_present = True
            break

    if root_cause and root_cause != "Undetermined" and not root_present:
        summary.append(
            {
                "root_cause": root_cause,
                "probability": confidence,
                "evidence": result.get("evidence", [])[:3],
            }
        )

    other_items = [item for item in ranked if item.get("root_cause") != root_cause]
    other_score_total = sum(max(0, int(item.get("score", 0))) for item in other_items)
    remaining = max(0, 100 - confidence)

    for item in ranked:
        score = max(0, int(item.get("score", 0)))
        if item.get("root_cause") == root_cause:
            probability = confidence
        elif other_score_total > 0:
            probability = round(remaining * score / other_score_total)
        else:
            probability = 0
        summary.append(
            {
                "root_cause": item.get("root_cause", "Unknown"),
                "probability": probability,
                "evidence": item.get("evidence", [])[:3],
            }
        )

    result = dict(result)
    result["hypothesis_summary"] = summary[:5]
    return result


def _is_placeholder(value: str | None) -> bool:
    return not value or value.strip().upper().startswith("REPLACE_ME")


def _iter_model_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("data", "listData", "models", "items"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _parse_llm_json(content: str) -> dict[str, Any]:
    """Parse JSON even when the model wraps it in markdown or prose."""

    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()

    try:
        parsed = json.loads(stripped)
        return parsed if isinstance(parsed, dict) else {}
    except json.JSONDecodeError:
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(content):
        if char not in "{[":
            continue
        try:
            parsed, _ = decoder.raw_decode(content[index:])
        except json.JSONDecodeError:
            continue
        return parsed if isinstance(parsed, dict) else {}
    return {}


def resolve_llm_model(api_key: str, base_url: str) -> str | None:
    """Resolve a model id from the OpenAI-compatible /models endpoint.

    If LLM_MODEL is not explicitly configured, this lets the user only provide
    the GreenNode MaaS API key and a provider preference such as "minimax".
    """

    provider_preference = os.getenv("LLM_MODEL_PROVIDER", "minimax").lower()
    try:
        response = requests.get(
            f"{base_url.rstrip('/')}/models",
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=15,
        )
        response.raise_for_status()
        models = _iter_model_items(response.json())
    except Exception:
        return None

    preferred = []
    fallback = []
    for model in models:
        model_id = model.get("id") or model.get("path") or model.get("code") or model.get("name")
        if not model_id:
            continue
        searchable = " ".join(
            str(model.get(key, "")) for key in ("id", "path", "code", "name", "provider", "description")
        ).lower()
        status = str(model.get("modelStatus") or model.get("status") or "").upper()
        disabled = status in {"DISABLED", "INACTIVE", "DELETED"}
        if provider_preference and provider_preference in searchable and not disabled:
            preferred.append(str(model_id))
        elif not disabled:
            fallback.append(str(model_id))

    if preferred:
        return preferred[0]
    if fallback:
        return fallback[0]
    return None


def llm_refine_root_cause(
    incident: dict[str, Any],
    timeline: list[dict[str, Any]],
    heuristic_result: dict[str, Any],
) -> dict[str, Any]:
    """Optionally ask an OpenAI-compatible LLM to refine the RCA result.

    The function is disabled unless AIOPS_USE_LLM=true and the LLM env vars are
    configured. It returns the heuristic result on any error.
    """

    if os.getenv("AIOPS_USE_LLM", "false").lower() not in {"1", "true", "yes"}:
        return heuristic_result

    api_key = os.getenv("LLM_API_KEY")
    base_url = os.getenv("LLM_BASE_URL")
    model = os.getenv("LLM_MODEL")
    if _is_placeholder(api_key) or _is_placeholder(base_url):
        return heuristic_result
    if _is_placeholder(model):
        model = resolve_llm_model(api_key=api_key, base_url=base_url or "")
    if not model:
        result = dict(heuristic_result)
        result["llm_error"] = "LLM_MODEL is not set and no suitable model could be resolved from /models"
        return result

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key, base_url=base_url)
        prompt = {
            "incident": incident,
            "timeline": timeline,
            "heuristic_result": heuristic_result,
            "instruction": (
                "Return compact JSON with root_cause, confidence, evidence, and needs_more_evidence. "
                "Distinguish symptom, user impact, and root cause. Prefer a candidate root cause from "
                "heuristic_result when its evidence matches the timeline. Do not invent a root cause when "
                "the timeline only shows symptoms; return root_cause='Undetermined' and needs_more_evidence=true. "
                "For camera or endpoint down reports, treat switch access-port admin/oper down, PoE loss, "
                "port errors, or mistaken config shutdown as stronger root-cause evidence than the camera "
                "being unreachable itself. "
                "Do not recommend destructive actions."
            ),
        }
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are an AIOps incident investigation analyst."},
                {"role": "user", "content": json.dumps(prompt, ensure_ascii=True)},
            ],
            temperature=0.1,
        )
        content = response.choices[0].message.content or "{}"
        parsed = _parse_llm_json(content)
        if parsed.get("root_cause"):
            parsed.setdefault("method", "llm")
            parsed.setdefault("llm_model", model)
            parsed.setdefault("ranked_hypotheses", heuristic_result.get("ranked_hypotheses", []))
            return parsed
    except Exception as exc:  # pragma: no cover - defensive fallback for optional LLM path
        result = dict(heuristic_result)
        result["llm_error"] = str(exc)
        return result

    return heuristic_result


def analyze_root_cause(incident: dict[str, Any], timeline: list[dict[str, Any]]) -> dict[str, Any]:
    heuristic = heuristic_root_cause(incident, timeline)
    refined = llm_refine_root_cause(incident, timeline, heuristic)
    return _with_hypothesis_probabilities(refined)
