import unittest

from evidence.models import EmailMetadata
from evidence.header_analyzer import analyze_headers


class TestHeaderAnalyzer(unittest.TestCase):

    def test_reply_to_mismatch(self):

        metadata = EmailMetadata(
            sender="security@example.com",
            reply_to="attacker@example.org",
            return_path="bounce@example.com"
        )

        signals = analyze_headers(metadata)

        signal_ids = [
            signal["signal_id"]
            for signal in signals
        ]

        self.assertIn(
            "HDR-001",
            signal_ids
        )

    def test_matching_domains(self):

        metadata = EmailMetadata(
            sender="security@example.com",
            reply_to="support@example.com",
            return_path="bounce@example.com"
        )

        signals = analyze_headers(metadata)

        signal_ids = [
            signal["signal_id"]
            for signal in signals
        ]

        self.assertNotIn(
            "HDR-001",
            signal_ids
        )

        self.assertNotIn(
            "HDR-002",
            signal_ids
        )


if __name__ == "__main__":
    unittest.main()