from datetime import datetime
import os
from pathlib import Path
import unittest
from unittest.mock import patch


os.environ["AIOPS_USE_LLM"] = "false"
os.environ["AIOPS_STORE_PATH"] = "data/test_incidents.sqlite3"

from aiops_incident_agent.catalog import REQUIRED_SCENARIO_KEYS
from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset, generate_required_scenarios
from aiops_incident_agent.intake import build_incident_from_report
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.telegram import format_telegram_payload
from aiops_incident_agent.timeline import build_timeline
from main import INVESTIGATION_SESSIONS, handler


STORE_PATH = Path(os.environ["AIOPS_STORE_PATH"])


class AIOpsRCARebuildTest(unittest.TestCase):
    def setUp(self):
        INVESTIGATION_SESSIONS.clear()
        if STORE_PATH.exists():
            STORE_PATH.unlink()

    def test_required_scenarios_are_generated(self):
        incidents = generate_required_scenarios(seed=123)
        self.assertEqual(len(incidents), 10)
        self.assertEqual({incident["scenario_key"] for incident in incidents}, set(REQUIRED_SCENARIO_KEYS))
        for incident in incidents:
            self.assertIn("ground_truth_root_cause", incident)
            self.assertIn("alert", incident)
            self.assertIn("logs", incident)
            self.assertIn("metrics", incident)
            self.assertIn("topology", incident)
            self.assertIn("recent_changes", incident)
            self.assertIn("baseline", incident)
            self.assertTrue(any(log.get("signal") == "related" for log in incident["logs"]))
            self.assertTrue(any(log.get("signal") == "noise" for log in incident["logs"]))
            self.assertEqual({"before", "during", "after"}, {metric.get("phase") for metric in incident["metrics"]})

    def test_timeline_schema_and_sorting(self):
        incident = generate_required_scenarios(seed=321)[0]
        timeline = build_timeline(incident)
        parsed = [datetime.fromisoformat(event["time"].replace("Z", "+00:00")) for event in timeline]
        self.assertEqual(parsed, sorted(parsed))
        for event in timeline:
            self.assertIn("time", event)
            self.assertIn("event", event)
            self.assertIn("source", event)
            self.assertIn(event["type"], {"change", "symptom", "impact", "evidence", "root_cause_candidate"})

    def test_each_required_scenario_analyzes_to_ground_truth(self):
        incidents = generate_required_scenarios(seed=42)
        for incident in incidents:
            with self.subTest(incident=incident["scenario_key"]):
                assessment = analyze_incident(incident, persist=False)
                self.assertEqual(assessment["most_likely_root_cause"], incident["ground_truth_root_cause"])
                self.assertGreaterEqual(assessment["confidence"], 70)
                self.assertIn(assessment["status"], {"need_verification", "confirmed"})
                self.assertIn("summary", assessment)
                self.assertIn("timeline", assessment)
                self.assertIn("root_cause_hypotheses", assessment)
                self.assertIn("recommended_actions", assessment)
                self.assertIn("telegram_report", assessment)
                self.assertIn("<b>AIOps RCA Alert</b>", assessment["telegram_report"])
                self.assertEqual(format_telegram_payload(assessment["telegram_report"])["parse_mode"], "HTML")

    def test_dataset_accuracy_threshold(self):
        incidents = generate_dataset(per_category=20, seed=42)
        evaluation = evaluate_incidents(incidents)
        self.assertEqual(evaluation["total"], 60)
        self.assertGreaterEqual(evaluation["accuracy"], 0.70)

    def test_manual_vague_report_is_insufficient_data(self):
        normalized = build_incident_from_report({"message": "please check this issue", "severity": "warning"})
        assessment = analyze_incident(normalized["incident"], persist=False)
        self.assertEqual(assessment["most_likely_root_cause"], "Undetermined")
        self.assertEqual(assessment["status"], "insufficient_data")
        self.assertLess(assessment["confidence"], 70)

    def test_handler_generate_analyze_latest(self):
        generated = handler({"operation": "generate", "incident_type": "broadcast-loop-aruba", "seed": 2609}, None)
        self.assertEqual(generated["status"], "success")
        incident = generated["incident"]
        analyzed = handler({"operation": "analyze", "incident": incident, "send_telegram": False}, None)
        self.assertEqual(analyzed["status"], "success")
        self.assertEqual(analyzed["assessment"]["most_likely_root_cause"], incident["ground_truth_root_cause"])
        latest = handler({"operation": "latest"}, None)
        self.assertTrue(latest["latest"]["found"])
        self.assertEqual(latest["latest"]["assessment"]["incident_id"], incident["incident_id"])

    def test_handler_generate_all_required_scenarios(self):
        response = handler({"operation": "generate", "all_required_scenarios": True, "seed": 123}, None)
        self.assertEqual(response["status"], "success")
        self.assertEqual(len(response["incidents"]), 10)

    def test_telegram_random_demo_request(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler({"operation": "telegram_chat", "chat_id": 12345, "text": "tao incident random"}, None)
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["intent"], "proactive_alert")
        self.assertIn("assessment", response)
        self.assertIn("AIOps RCA Alert", response["assessment"]["telegram_report"])

    def test_telegram_chat_camera_down_maps_to_interface_flapping(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler({"operation": "telegram_chat", "chat_id": 456, "text": "camera 01 down, check port switch co bat thuong khong"}, None)
            follow_up = handler({"operation": "telegram_chat", "chat_id": 456, "text": "co change config trong khoang 09:30-10:00 khong"}, None)
        self.assertEqual(response["intent"], "start_investigation")
        self.assertEqual(response["intake"]["matched_template"], "interface-flapping")
        self.assertEqual(response["assessment"]["most_likely_root_cause"], "Interface flapping")
        self.assertIn("incident demo", response["reply"])
        self.assertEqual(follow_up["intent"], "continue_investigation")
        self.assertIn("Change/config", follow_up["reply"])


if __name__ == "__main__":
    unittest.main()
