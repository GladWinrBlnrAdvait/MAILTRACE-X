import unittest

from evidence.ioc_extractor import extract_iocs


class TestIOCExtractor(unittest.TestCase):

    def test_ioc_extraction(self):

        text = """
        Contact analyst@test.example.

        Visit:
        https://portal.test.example/login

        Server:
        192.0.2.50
        """

        result = extract_iocs(text)

        self.assertIn(
            "https://portal.test.example/login",
            result.urls
        )

        self.assertIn(
            "portal.test.example",
            result.domains
        )

        self.assertIn(
            "test.example",
            result.domains
        )

        self.assertIn(
            "192.0.2.50",
            result.ips
        )

        self.assertIn(
            "analyst@test.example",
            result.emails
        )

    def test_invalid_ip_rejected(self):

        text = """
        Valid: 192.0.2.50
        Invalid: 999.999.999.999
        """

        result = extract_iocs(text)

        self.assertIn(
            "192.0.2.50",
            result.ips
        )

        self.assertNotIn(
            "999.999.999.999",
            result.ips
        )


if __name__ == "__main__":
    unittest.main()