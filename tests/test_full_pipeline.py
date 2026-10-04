import unittest

from evidence.email_parser import parse_email


class TestFullPipeline(unittest.TestCase):

    def test_complete_email_analysis(self):

        evidence = parse_email(
            "samples/sample.eml",
            "PIPELINE-001"
        )

        # -------------------------
        # Parsing
        # -------------------------

        self.assertEqual(
            evidence.case_id,
            "PIPELINE-001"
        )

        self.assertEqual(
            evidence.metadata.subject,
            "Urgent Account Verification Required"
        )

        # -------------------------
        # IOC extraction
        # -------------------------

        self.assertIn(
            "https://login.example.com/verify",
            evidence.iocs.urls
        )

        self.assertIn(
            "192.0.2.20",
            evidence.iocs.ips
        )

        self.assertIn(
            "login.example.com",
            evidence.iocs.domains
        )

        # -------------------------
        # Authentication
        # -------------------------

        self.assertEqual(
            evidence.authentication.spf,
            "fail"
        )

        self.assertEqual(
            evidence.authentication.dkim,
            "none"
        )

        self.assertEqual(
            evidence.authentication.dmarc,
            "fail"
        )

        # -------------------------
        # Evidence signals
        # -------------------------

        signal_ids = [
            signal["signal_id"]
            for signal in evidence.evidence_signals
        ]

        self.assertIn(
            "HDR-001",
            signal_ids
        )

        self.assertIn(
            "AUTH-001",
            signal_ids
        )

        self.assertIn(
            "AUTH-004",
            signal_ids
        )


if __name__ == "__main__":
    unittest.main()