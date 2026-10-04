import unittest
from email import policy
from email.parser import BytesParser

from evidence.authentication import analyze_authentication
from evidence.signal_engine import generate_authentication_signals


class TestAuthentication(unittest.TestCase):

    def setUp(self):

        with open("samples/sample.eml", "rb") as file:
            self.message = BytesParser(
                policy=policy.default
            ).parse(file)

    def test_authentication_results(self):

        authentication = analyze_authentication(
            self.message
        )

        self.assertEqual(
            authentication.spf,
            "fail"
        )

        self.assertEqual(
            authentication.dkim,
            "none"
        )

        self.assertEqual(
            authentication.dmarc,
            "fail"
        )

    def test_authentication_signals(self):

        authentication = analyze_authentication(
            self.message
        )

        signals = generate_authentication_signals(
            authentication
        )

        signal_ids = [
            signal["signal_id"]
            for signal in signals
        ]

        self.assertIn(
            "AUTH-001",
            signal_ids
        )

        self.assertIn(
            "AUTH-004",
            signal_ids
        )

        # DKIM = none, not fail
        self.assertNotIn(
            "AUTH-003",
            signal_ids
        )


if __name__ == "__main__":
    unittest.main()