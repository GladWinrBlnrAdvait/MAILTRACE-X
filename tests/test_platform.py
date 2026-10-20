import unittest

from backend.detection import detect_phishing
from backend.risk import calculate_risk
from evidence.email_parser import parse_email


class TestPlatform(unittest.TestCase):
    def test_suspicious_email_has_explainable_verdict_and_risk(self):
        evidence = parse_email("samples/sample.eml", "PLATFORM-001")
        detection = detect_phishing(evidence)
        risk = calculate_risk(evidence, detection)
        self.assertEqual(detection.classification, "phishing")
        self.assertGreater(detection.phishing_probability, .7)
        self.assertGreaterEqual(risk.score, 60)
        self.assertIn("Email authentication checks failed", risk.reasons)


if __name__ == "__main__":
    unittest.main()
