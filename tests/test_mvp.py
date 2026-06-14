from datetime import datetime
import os
import unittest
from unittest.mock import patch

os.environ["AIOPS_USE_LLM"] = "false"

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.telegram import format_telegram_payload
from aiops_incident_agent.timeline import build_timeline
from main import handler


class AIOpsMVPTest(unittest.TestCase):
    def test_generate_balanced_dataset(self):
        incidents = generate_dataset(per_category=20, seed=123)
        self.assertEqual(len(incidents), 60)
        counts = {"network": 0, "system": 0, "security": 0}
        for incident in incidents:
            counts[incident["category"]] += 1
            self.assertIn("ground_truth_root_cause", incident)
            self.assertIn("alert", incident)
            self.assertIn("metrics", incident)
            self.assertIn("logs", incident)
            self.assertIn("topology", incident)
            self.assertIn("change_history", incident)
        self.assertEqual(counts, {"network": 20, "system": 20, "security": 20})

    def test_timeline_is_sorted(self):
        incident = generate_dataset(per_category=1, seed=321)[0]
        timeline = build_timeline(incident)
        parsed = [datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) for event in timeline]
        self.assertEqual(parsed, sorted(parsed))

    def test_analyze_single_incident(self):
        incident = generate_dataset(per_category=1, seed=42)[0]
        assessment = analyze_incident(incident)
        self.assertIn("timeline", assessment)
        self.assertIn("correlation", assessment)
        self.assertIn("root_cause_analysis", assessment)
        self.assertIn("recommendations", assessment)
        self.assertIn("telegram_report", assessment)
        self.assertEqual(assessment["root_cause_analysis"]["root_cause"], incident["ground_truth_root_cause"])
        self.assertIn("hypothesis_summary", assessment["root_cause_analysis"])
        self.assertIn("<b>AIOps Incident Alert</b>", assessment["telegram_report"])
        self.assertIn("<b>Giả định & xác suất</b>", assessment["telegram_report"])
        self.assertIn("<code>", assessment["telegram_report"])
        payload = format_telegram_payload(assessment["telegram_report"])
        self.assertEqual(payload["parse_mode"], "HTML")
        self.assertNotIn("reply_markup", payload)
        self.assertNotIn("Use the buttons", assessment["telegram_report"])

    def test_accuracy_threshold(self):
        incidents = generate_dataset(per_category=20, seed=42)
        evaluation = evaluate_incidents(incidents)
        self.assertGreaterEqual(evaluation["accuracy"], 0.70)

    def test_agentbase_generate_random_incident(self):
        response = handler({"operation": "generate", "incident_type": "random", "seed": 2609}, None)
        self.assertEqual(response["status"], "success")
        self.assertIn("incident_type", response)
        self.assertIn("ground_truth_root_cause", response["incident"])

    def test_agentbase_demo_alert_without_telegram(self):
        response = handler(
            {"operation": "demo_alert", "incident_type": "random", "seed": 2610, "send_telegram": False},
            None,
        )
        self.assertEqual(response["status"], "success")
        self.assertIn("incident", response)
        self.assertIn("assessment", response)
        self.assertNotIn("telegram_delivery", response["assessment"])

    def test_agentbase_proactive_alert_without_telegram(self):
        response = handler(
            {"operation": "proactive_alert", "incident_type": "random", "seed": 2613, "send_telegram": False},
            None,
        )
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["workflow"], "proactive_alert")
        self.assertIn("reply", response)
        self.assertNotIn("telegram_delivery", response["assessment"])

    def test_agentbase_record_incident_from_message(self):
        response = handler(
            {
                "operation": "record_incident",
                "message": "Fortigate CPU high and session spike after firewall policy change",
                "source": "FGT-HQ-01",
                "severity": "critical",
                "send_telegram": False,
            },
            None,
        )
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["workflow"], "record_incident")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Firewall Session Exhaustion")
        self.assertIn("reply", response)

    def test_agentbase_record_incident_undetermined_when_too_vague(self):
        response = handler(
            {"operation": "record_incident", "message": "Need someone to look at this", "send_telegram": False},
            None,
        )
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Undetermined")
        self.assertTrue(response["assessment"]["root_cause_analysis"]["needs_more_evidence"])

    def test_telegram_chat_random_incident_request(self):
        update = {
            "update_id": 1,
            "message": {"message_id": 1, "chat": {"id": 12345}, "text": "tạo ra incident ngẫu nhiên"},
        }
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(update, None)
        self.assertEqual(response["status"], "success")
        self.assertEqual(response["workflow"], "telegram_chat")
        self.assertEqual(response["intent"], "proactive_alert")
        self.assertIn("assessment", response)
        self.assertEqual(response["telegram_delivery"]["sent"], True)

    def test_telegram_chat_internet_slow_maps_to_congestion(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12345,
                    "text": "internet chậm kết nối hãy kiểm tra có gì bất thường hay không",
                },
                None,
            )
        self.assertEqual(response["intent"], "record_incident")
        self.assertEqual(response["intake"]["matched_template"], "internet-congestion")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Internet Congestion")

    def test_telegram_chat_db_disconnect_maps_to_service_crash(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12345,
                    "text": "mất kết nối server DB-01 có gì bất thường không",
                },
                None,
            )
        self.assertEqual(response["intake"]["matched_template"], "service-crash")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Service Crash")

    def test_telegram_chat_port_flap_maps_to_interface_flapping(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12345,
                    "text": "port ge-0/0/1 bị flap nhiều lần có ghi nhận gì bất thường không",
                },
                None,
            )
        self.assertEqual(response["intake"]["matched_template"], "interface-flapping")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Interface Flapping")

    def test_telegram_chat_camera_down_maps_to_access_port_down(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12346,
                    "text": "camera 01 down, kiểm tra có gì bất thường không",
                },
                None,
            )
        self.assertEqual(response["intake"]["matched_template"], "camera-access-port-down")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Mistaken Camera Access Port Shutdown")
        self.assertIn("ge-0/0/1", response["assessment"]["telegram_report"])

    def test_telegram_follow_up_checks_change_window(self):
        update = {
            "update_id": 2,
            "message": {"message_id": 1, "chat": {"id": 12347}, "text": "camera 01 down"},
        }
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            first = handler(update, None)

        follow_up = {
            "update_id": 3,
            "message": {
                "message_id": 2,
                "chat": {"id": 12347},
                "text": "trong khoảng thời gian từ 03:00-03:10 có ai change cấu hình không",
            },
        }
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            detail = handler(follow_up, None)

        self.assertEqual(first["assessment"]["root_cause_analysis"]["root_cause"], "Mistaken Camera Access Port Shutdown")
        self.assertEqual(detail["workflow"], "telegram_chat")
        self.assertEqual(detail["intent"], "follow_up")
        self.assertIn("Change / Config Check", detail["reply"])
        self.assertIn("Shutdown access port ge-0/0/1", detail["reply"])
        self.assertEqual(detail["telegram_delivery"]["sent"], True)


if __name__ == "__main__":
    unittest.main()
