"""Offline tests: related-case links must survive a server restart."""
import json
import unittest
from unittest.mock import patch

from correlation import service
from correlation.persistence import graph_from_correlation
from evidence.models import AttachmentEvidence, EmailEvidence, IOCCollection

HASH = "b" * 64


def fake_dns(domain):
    return {"domain": domain, "status": "ok", "A": ["203.0.113.10"], "AAAA": [], "MX": [], "NS": []}


def fake_ip(ip):
    return {"ip": ip, "status": "ok", "asn": "AS64500", "asn_description": "TEST"}


def fake_rep(ip):
    return {"ip": ip, "status": "ok", "abuse_score": 0, "total_reports": 0}


def fake_hash(sha):
    return {"sha256": sha, "status": "ok", "found": False}


def make_case(case_id, domains=(), hashes=()):
    return EmailEvidence(
        case_id=case_id,
        iocs=IOCCollection(domains=list(domains)),
        attachments=[AttachmentEvidence("f.bin", "application/octet-stream", 1, h) for h in hashes],
    )


@patch("correlation.graph_builder.check_hash_reputation", fake_hash)
@patch("correlation.graph_builder.check_ip_reputation", fake_rep)
@patch("correlation.graph_builder.lookup_ip", fake_ip)
@patch("correlation.graph_builder.resolve_domain", fake_dns)
class PersistenceTests(unittest.TestCase):
    def setUp(self):
        service._master.clear()

    def save_like_the_database(self, evidence):
        """Analyse a case, then pass it through JSON like SQLite storage does."""
        output = service.enrich_evidence(evidence)
        return json.loads(json.dumps({"correlation": output.model_dump()}))

    def test_graph_rebuilds_with_correct_node_types(self):
        saved = self.save_like_the_database(make_case("A", domains=["evil.test"], hashes=[HASH]))
        graph = graph_from_correlation(saved["correlation"])
        self.assertEqual(graph.nodes["A"]["type"], "case")
        self.assertEqual(graph.nodes["evil.test"]["type"], "domain")
        self.assertEqual(graph.nodes[HASH]["type"], "hash")
        self.assertEqual(graph.nodes["AS64500"]["type"], "asn")

    def test_links_survive_restart(self):
        saved = self.save_like_the_database(make_case("A", hashes=[HASH]))
        service._master.clear()                       # simulate a server restart
        self.assertEqual(service.load_cases([saved]), 1)
        out = service.enrich_evidence(make_case("B", hashes=[HASH]))
        self.assertEqual(out.related_cases[0].case_id, "A")

    def test_without_loading_the_link_is_lost(self):
        self.save_like_the_database(make_case("A", hashes=[HASH]))
        service._master.clear()                       # restart, nothing reloaded
        out = service.enrich_evidence(make_case("B", hashes=[HASH]))
        self.assertEqual(out.related_cases, [])

    def test_cases_without_correlation_are_skipped(self):
        self.assertEqual(service.load_cases([None, {}, {"correlation": None}]), 0)


if __name__ == "__main__":
    unittest.main()
