import copy
import unittest

from backend.detection import detect_phishing
from backend.risk import calculate_risk
from evidence.email_parser import parse_email


class TestRiskDeduplication(unittest.TestCase):
    def setUp(self):
        self.evidence = parse_email("samples/sample.eml", "RISK-001")
        self.detection = detect_phishing(self.evidence)

    def test_duplicate_signal_url_and_attachment_count_once(self):
        baseline = calculate_risk(self.evidence, self.detection)
        duplicate = copy.deepcopy(self.evidence)
        duplicate.evidence_signals.append(copy.deepcopy(duplicate.evidence_signals[0]))
        duplicate.iocs.urls.append(duplicate.iocs.urls[0].upper())
        if duplicate.attachments:
            duplicate.attachments.append(copy.deepcopy(duplicate.attachments[0]))
        result = calculate_risk(duplicate, self.detection)
        self.assertEqual(result.score, baseline.score)

    def test_score_is_bounded(self):
        inflated = copy.deepcopy(self.evidence)
        inflated.evidence_signals = [{"signal_id": f"X-{i}", "severity": "critical", "description": "test"} for i in range(50)]
        inflated.iocs.urls = [f"https://{i}.example.test" for i in range(50)]
        self.assertLessEqual(calculate_risk(inflated, self.detection).score, 100)


if __name__ == "__main__":
    unittest.main()
