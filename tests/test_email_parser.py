import unittest

from evidence.email_parser import parse_email


class TestEmailParser(unittest.TestCase):

    def test_basic_email_parsing(self):

        evidence = parse_email(
            "samples/sample.eml",
            "TEST-001"
        )

        self.assertEqual(
            evidence.case_id,
            "TEST-001"
        )

        self.assertIn(
            "security@example.com",
            evidence.metadata.sender
        )

        self.assertEqual(
            evidence.metadata.subject,
            "Urgent Account Verification Required"
        )

        self.assertIn(
            "advait@example.net",
            evidence.metadata.recipients
        )

        self.assertGreater(
            len(evidence.received_headers),
            0
        )

        self.assertIn(
            "Your account will be suspended",
            evidence.body.text
        )


if __name__ == "__main__":
    unittest.main()