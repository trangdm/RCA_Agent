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
from main import INVESTIGATION_SESSIONS, handler


class AIOpsMVPTest(unittest.TestCase):
    def setUp(self):
        INVESTIGATION_SESSIONS.clear()

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
        self.assertIn("<b>AIOps Incident Assessment</b>", assessment["telegram_report"])
        self.assertIn("<code>", assessment["telegram_report"])
        self.assertEqual(format_telegram_payload(assessment["telegram_report"])["parse_mode"], "HTML")

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
        self.assertEqual(response["intent"], "start_investigation")
        self.assertEqual(response["intake"]["matched_template"], "internet-congestion")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Internet Congestion")
        self.assertIn("tạo incident demo", response["reply"])
        self.assertIn("Khá rõ rồi", response["reply"])

    def test_telegram_chat_db_disconnect_maps_to_service_crash(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12346,
                    "text": "mất kết nối server DB-01 có gì bất thường không",
                },
                None,
            )
        self.assertEqual(response["intent"], "start_investigation")
        self.assertEqual(response["intake"]["matched_template"], "service-crash")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Service Crash")

    def test_telegram_chat_port_flap_maps_to_interface_flapping(self):
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            response = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": 12347,
                    "text": "port ge-0/0/1 bị flap nhiều lần có ghi nhận gì bất thường không",
                },
                None,
            )
        self.assertEqual(response["intent"], "start_investigation")
        self.assertEqual(response["intake"]["matched_template"], "interface-flapping")
        self.assertEqual(response["assessment"]["root_cause_analysis"]["root_cause"], "Interface Flapping")

    def test_telegram_multi_turn_investigation_accumulates_context(self):
        chat_id = 77701
        with patch("main.send_telegram_report", return_value={"sent": True, "status_code": 200}):
            first = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": chat_id,
                    "text": "internet chậm từ 09:30-10:00, packet loss cao, user chi nhánh HCM bị ảnh hưởng",
                },
                None,
            )
            second = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": chat_id,
                    "text": "log firewall có bandwidth saturation và qos queue full; giả định của tôi là backup replication làm nghẽn WAN",
                },
                None,
            )
            question = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": chat_id,
                    "text": "timeline/log đáng chú ý là gì",
                },
                None,
            )
            runbook = handler(
                {
                    "operation": "telegram_chat",
                    "chat_id": chat_id,
                    "text": "cho tôi command/check runbook để verify sự cố này",
                },
                None,
            )

        self.assertEqual(first["intent"], "start_investigation")
        self.assertEqual(second["intent"], "continue_investigation")
        self.assertEqual(second["session"]["message_count"], 2)
        self.assertIn("09:30-10:00", second["session"]["time_windows"])
        self.assertEqual(second["assessment"]["root_cause_analysis"]["root_cause"], "Internet Congestion")
        self.assertIn("chạy lại RCA", second["reply"])
        self.assertIn("Mình dựa vào", second["reply"])
        self.assertIn("09:30:00 UTC", second["reply"])
        self.assertEqual(question["intent"], "continue_investigation")
        self.assertIn("Timeline đáng chú ý", question["reply"])
        self.assertEqual(runbook["intent"], "continue_investigation")
        self.assertIn("runbook/check/action", runbook["reply"])
        self.assertIn("Command/check gợi ý", runbook["reply"])
        self.assertIn("show interface", runbook["reply"])
        self.assertNotIn("Bạn gửi thêm giúp mình log raw", runbook["reply"])


if __name__ == "__main__":
    unittest.main()
