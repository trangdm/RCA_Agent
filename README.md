# AIOps Incident Investigation Agent

MVP AI agent for synthetic incident investigation on GreenNode AgentBase.

The agent does not connect to real infrastructure. It uses generated data only:
alerts, metrics, logs, topology, and change history.

## MVP Capabilities

- Generate synthetic incident JSON.
- Build a sorted timeline.
- Correlate related events into likely cause, symptom, and impact groups.
- Analyze the most likely root cause with deterministic reasoning, with optional LLM refinement.
- Generate safe immediate, verification, and prevention recommendations.
- Format and optionally send a Telegram incident assessment.
- Evaluate predictions against ground truth on a 60-incident synthetic dataset.

## Architecture

```text
Synthetic Incident Generator
  -> Incident Payload
  -> AIOps Agent
  -> Timeline Builder
  -> Correlation Engine
  -> Root Cause Analyzer
  -> Recommendation Engine
  -> Telegram Output
```

## Local Setup

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Optional local config:

```powershell
Copy-Item .env.example .env
```

For the hackathon setup, fill these values in `.env`:

```env
GREENNODE_CLIENT_ID=your-iam-client-id
GREENNODE_CLIENT_SECRET=your-iam-client-secret
LLM_API_KEY=your-greennode-maas-api-key
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_CHAT_ID=your-telegram-chat-id
```

For MiniMax, keep:

```env
LLM_MODEL_PROVIDER=minimax
LLM_MODEL=
```

When `LLM_MODEL` is blank, the agent calls the GreenNode MaaS `/models`
endpoint and auto-picks a MiniMax model. Set `AIOPS_USE_LLM=true` only when you
want LLM refinement. The offline heuristic path works with `AIOPS_USE_LLM=false`.

For GreenNode MaaS / OpenAI-compatible clients:

```text
LLM_BASE_URL=https://maas-llm-aiplatform-hcm.api.vngcloud.vn/v1
```

## Generate Synthetic Dataset

```powershell
python scripts/generate_dataset.py --per-category 20 --output data/generated/incidents.json
```

This creates:

- `data/generated/incidents.json`
- `incident.json` with the first generated incident

## Analyze One Incident

```powershell
python scripts/analyze_incident.py incident.json --output assessment.json
```

Send Telegram report if `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` are set:

```powershell
python scripts/analyze_incident.py incident.json --telegram
```

## Evaluate Accuracy

```powershell
python scripts/evaluate_dataset.py --per-category 20
```

Target: at least 70 percent accuracy on the synthetic dataset.

## AgentBase Invocation

The SDK exposes the handler at `POST /invocations`.

Generate one incident:

```json
{
  "operation": "generate",
  "incident_type": "random",
  "incident_id": "INC-DEMO"
}
```

Use a specific type by passing one of the catalog keys, for example
`broadcast-loop`, `disk-full`, or `brute-force-attack`.

Analyze an incident:

```json
{
  "operation": "analyze",
  "incident": {
    "incident_id": "INC-001",
    "alert": {"severity": "critical", "message": "Firewall CPU High"},
    "metrics": [],
    "logs": [],
    "topology": {},
    "change_history": []
  },
  "send_telegram": false
}
```

Evaluate generated incidents:

```json
{
  "operation": "evaluate",
  "per_category": 20
}
```

Generate a random incident, analyze it, and send the Telegram alert:

```json
{
  "operation": "demo_alert",
  "incident_type": "random",
  "send_telegram": true
}
```

For a dry run that does not send Telegram, set `send_telegram` to `false`.

Proactively generate, analyze, and notify a synthetic incident:

```json
{
  "operation": "proactive_alert",
  "incident_type": "random",
  "send_telegram": true
}
```

Record an incident reported by an operator, analyze it, and return a reply:

```json
{
  "operation": "record_incident",
  "message": "Fortigate CPU high, session count spikes after a firewall policy change. Users report slow internet.",
  "source": "FGT-HQ-01",
  "severity": "critical",
  "send_telegram": false
}
```

`record_incident` also accepts a full `incident` JSON payload if the caller
already has structured alert, metric, log, topology, and change-history data.

## Telegram Chat

Point the Telegram bot webhook to the AgentBase invocation endpoint:

```powershell
$endpoint = "https://<agentbase-endpoint-host>/invocations"
$token = "<telegram-bot-token>"
Invoke-RestMethod -Method Post `
  -Uri "https://api.telegram.org/bot$token/setWebhook" `
  -Body @{ url = $endpoint; drop_pending_updates = "true" }
```

After that, users can chat directly with the bot:

```text
tạo ra incident ngẫu nhiên
internet chậm kết nối hãy kiểm tra có gì bất thường hay không
mất kết nối server DB-01 có gì bất thường không
port ge-0/0/1 bị flap nhiều lần có ghi nhận gì bất thường không
```

The agent treats open-ended Telegram messages as demo incident intake: it
generates the closest related synthetic incident, runs RCA, and sends the
formatted Telegram assessment back to the same chat.

Telegram alerts are summary-first:

- Top root cause and confidence.
- Top hypotheses with estimated probabilities.
- Short timeline snapshot with truncated log text.
- One immediate next action.
- Inline buttons for `Timeline`, `Evidence`, `Actions`, and `Full` detail.

## Proactive Alerting Strategy

In this MVP the agent does not connect to real infrastructure, so proactive
alerting is represented by a scheduler or webhook calling:

```json
{
  "operation": "proactive_alert",
  "incident_type": "random",
  "send_telegram": true
}
```

For a real deployment, the same workflow can be driven by a lightweight poller:

1. Every N minutes, query logs/metrics for a time window such as `now-5m..now`.
2. Normalize raw records into the same incident contract: alert, metrics, logs,
   topology, and change history.
3. Apply rule/anomaly triggers, for example error-rate spike, repeated port
   flaps, CPU/session threshold breach, DNS timeout rate, or DB connectivity
   failures.
4. Deduplicate with a fingerprint such as `root_cause + impacted_node +
   service + window`, then apply a cooldown to avoid Telegram spam.
5. Send only the compact RCA alert to Telegram; keep full timeline/evidence
   behind buttons.

This keeps the chat readable while preserving enough forensic detail for
follow-up investigation.

## Run Server Locally

```powershell
python main.py
```

Health check:

```powershell
curl.exe http://127.0.0.1:8080/health
```

## Docker

```powershell
docker build --platform linux/amd64 -t rca-agent:test .
docker run --rm -p 8080:8080 --env-file .env rca-agent:test
```

## Project Structure

```text
aiops_incident_agent/
  analyzer.py
  catalog.py
  correlation.py
  evaluator.py
  generator.py
  pipeline.py
  recommendations.py
  telegram.py
  timeline.py
scripts/
  analyze_incident.py
  evaluate_dataset.py
  generate_dataset.py
tests/
  test_mvp.py
main.py
Dockerfile
```

## Safety

The recommendation engine avoids destructive actions such as deleting data,
factory-resetting devices, or disabling security controls without approval.
