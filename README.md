# AIOps RCA Agent

Synthetic MVP agent for incident investigation on GreenNode AgentBase.

The agent does not connect to real ELK, Wazuh, Prometheus, Grafana, CheckMK,
Fortigate, or VMware systems. It generates and analyzes synthetic incident data
for demo, testing, and RCA reasoning.

## Flow

```text
Synthetic Incident Generator
  -> Alert + Logs + Metrics + Topology + Change History
  -> AIOps RCA Agent
  -> Timeline Builder
  -> Event Correlation
  -> Root Cause Analysis
  -> Recommendation
  -> Telegram Alert
```

## Incident Input Contract

```json
{
  "incident_id": "",
  "alert": {},
  "logs": [],
  "metrics": [],
  "topology": {},
  "recent_changes": [],
  "baseline": {},
  "ground_truth_root_cause": ""
}
```

`change_history` is still accepted as a backward-compatible alias for
`recent_changes`.

## Required Synthetic Scenarios

The generator includes 10 MVP scenarios:

1. Broadcast loop on Aruba switch
2. MAC flapping on core switch
3. Fortigate session spike causing high CPU
4. DNS server timeout
5. Linux server disk full
6. Windows service crash
7. VMware datastore full
8. Interface flapping
9. Routing issue
10. Brute force attack detected by Wazuh

Each generated incident has related logs, noise logs, before/during/after
metrics, topology, recent changes, baseline, and ground truth.

## RCA Output Contract

`analyze_incident()` returns the internal RCA JSON directly:

```json
{
  "incident_id": "",
  "severity": "",
  "summary": "",
  "timeline": [
    {
      "time": "",
      "event": "",
      "source": "",
      "type": "change|symptom|impact|evidence|root_cause_candidate"
    }
  ],
  "symptoms": [],
  "impact": "",
  "root_cause_hypotheses": [],
  "most_likely_root_cause": "",
  "confidence": 0,
  "evidence": [],
  "recommended_actions": {
    "immediate_actions": [],
    "verification_actions": [],
    "long_term_prevention": []
  },
  "missing_data": [],
  "status": "need_verification|confirmed|insufficient_data"
}
```

If confidence is below 70, the agent does not confirm a root cause and returns
`status=insufficient_data`.

## Local Setup

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Fill `.env` with your GreenNode IAM, MaaS API key, and Telegram values:

```env
GREENNODE_CLIENT_ID=your-iam-client-id
GREENNODE_CLIENT_SECRET=your-iam-client-secret
LLM_API_KEY=your-greennode-maas-api-key
TELEGRAM_BOT_TOKEN=your-telegram-bot-token
TELEGRAM_CHAT_ID=your-telegram-chat-id
```

The deterministic RCA path works without calling the LLM. Keep
`AIOPS_USE_LLM=false` for stable demo behavior.

## CLI

Generate a balanced dataset:

```powershell
python scripts/generate_dataset.py --per-category 20 --output data/generated/incidents.json
```

Analyze one incident:

```powershell
python scripts/analyze_incident.py incident.json --output assessment.json
```

Evaluate accuracy:

```powershell
python scripts/evaluate_dataset.py --per-category 20
```

## AgentBase Operations

Generate one incident:

```json
{
  "operation": "generate",
  "incident_type": "broadcast-loop-aruba"
}
```

Generate all 10 required scenarios:

```json
{
  "operation": "generate",
  "all_required_scenarios": true
}
```

Analyze a provided incident:

```json
{
  "operation": "analyze",
  "incident": {
    "incident_id": "INC-001",
    "alert": {"severity": "critical", "message": "Firewall CPU High"},
    "logs": [],
    "metrics": [],
    "topology": {},
    "recent_changes": [],
    "baseline": {}
  },
  "send_telegram": false
}
```

Generate, analyze, and optionally send a Telegram alert:

```json
{
  "operation": "proactive_alert",
  "incident_type": "random",
  "send_telegram": true
}
```

Record an operator report:

```json
{
  "operation": "record_incident",
  "message": "camera 01 down, check port switch co bat thuong khong",
  "send_telegram": false
}
```

Get latest stored analysis:

```json
{
  "operation": "latest"
}
```

Send a Telegram test:

```json
{
  "operation": "telegram_test",
  "text": "AIOps RCA Agent Telegram test message."
}
```

## Telegram Chat

Point the Telegram webhook to the AgentBase `/invocations` endpoint. Then you
can chat naturally:

```text
tao incident random
internet cham tu 09:30-10:00, packet loss cao
camera 01 down, check port switch co bat thuong khong
mat ket noi server DB-01 sau deploy
port ge-0/0/1 flap nhieu lan
co change config trong khoang 09:30-10:00 khong
timeline dang chu y la gi
root cause hien tai va evidence la gi
cho toi runbook/check an toan
```

The first incident-like message opens an investigation session. Follow-up
messages add evidence, impact, suspected objects, time windows, or questions.
The agent rebuilds the synthetic incident context and reruns RCA each turn.

## Tests

```powershell
venv\Scripts\python.exe -m unittest discover -s tests -v
```

Current tests verify the 10 required scenarios, RCA schema, Telegram format,
chat intake, SQLite latest storage, and at least 70 percent synthetic accuracy.

## Safety

Recommendations are verification-first. The agent does not suggest destructive
actions such as deleting production data, factory-resetting devices, or
disabling security controls without validation.
