"""Offline tests for hash reputation. No network: requests.post is faked."""
import os
import unittest
from unittest.mock import MagicMock, patch

import requests

from correlation.risk_rules import score_hash
from threat_intelligence.hash_reputation import check_hash_reputation

GOOD = "a" * 64


def fake_response(body):
    response = MagicMock()
    response.json.return_value = body
    response.raise_for_status.return_value = None
    return response


class HashReputationTests(unittest.TestCase):
    def setUp(self):
        check_hash_reputation.cache_clear()

    @patch.dict(os.environ, {}, clear=True)
    def test_no_key_means_offline_mode(self):
        self.assertEqual(check_hash_reputation(GOOD)["status"], "no_api_key")

    @patch.dict(os.environ, {"ABUSE_CH_KEY": "x"})
    def test_invalid_hash_is_rejected_without_a_request(self):
        with patch("requests.post") as post:
            self.assertEqual(check_hash_reputation("nothex")["status"], "invalid_hash")
            post.assert_not_called()

    @patch.dict(os.environ, {"ABUSE_CH_KEY": "x"})
    def test_known_malware(self):
        body = {"query_status": "ok",
                "data": [{"signature": "Emotet", "file_type": "doc", "tags": ["doc"]}]}
        with patch("requests.post", return_value=fake_response(body)):
            rep = check_hash_reputation(GOOD)
        self.assertTrue(rep["found"])
        score, reasons = score_hash(rep)
        self.assertEqual(score, 90)
        self.assertIn("Emotet", reasons[0])

    @patch.dict(os.environ, {"ABUSE_CH_KEY": "x"})
    def test_unknown_hash_scores_zero(self):
        with patch("requests.post", return_value=fake_response({"query_status": "hash_not_found"})):
            rep = check_hash_reputation(GOOD)
        self.assertEqual((rep["status"], rep["found"]), ("ok", False))
        self.assertEqual(score_hash(rep), (0, []))

    @patch.dict(os.environ, {"ABUSE_CH_KEY": "x"})
    def test_network_failure_is_not_cached(self):
        with patch("requests.post", side_effect=requests.ConnectionError):
            self.assertEqual(check_hash_reputation(GOOD)["status"], "lookup_failed")
        with patch("requests.post", return_value=fake_response({"query_status": "hash_not_found"})):
            self.assertEqual(check_hash_reputation(GOOD)["status"], "ok")


if __name__ == "__main__":
    unittest.main()
