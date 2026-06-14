from datetime import datetime
import unittest

from aiops_incident_agent.evaluator import evaluate_incidents
from aiops_incident_agent.generator import generate_dataset
from aiops_incident_agent.pipeline import analyze_incident
from aiops_incident_agent.telegram import format_telegram_payload
from aiops_incident_agent.timeline import build_timeline


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
        self.assertIn("<b>AIOps Incident Assessment</b>", assessment["telegram_report"])
        self.assertIn("<code>", assessment["telegram_report"])
        self.assertEqual(format_telegram_payload(assessment["telegram_report"])["parse_mode"], "HTML")

    def test_accuracy_threshold(self):
        incidents = generate_dataset(per_category=20, seed=42)
        evaluation = evaluate_incidents(incidents)
        self.assertGreaterEqual(evaluation["accuracy"], 0.70)


if __name__ == "__main__":
    unittest.main()
