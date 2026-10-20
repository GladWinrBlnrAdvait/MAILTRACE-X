"""Offline tests for the threat-intelligence and correlation layer.
DNS, RDAP and reputation lookups are replaced with fakes, so no network is used."""
import time
import unittest
from unittest.mock import patch

from correlation import service
from correlation.graph_builder import build_case_graph
from correlation.risk_rules import score_domain
from evidence.models import (AttachmentEvidence, EmailEvidence, IOCCollection)
from threat_intelligence.cache import cached

DNS = {  # domain -> list of A records
    "evil-one.test": ["203.0.113.10"],
    "evil-two.test": ["203.0.113.10"],      # same IP as evil-one
    "other.test": ["203.0.113.77"],         # different IP, same ASN
    "big-site.test": ["198.51.100.5"],      # Cloudflare-like (allowlisted ASN)
    "big-site-2.test": ["198.51.100.6"],
}
ASN = {
    "203.0.113.10": "AS64500", "203.0.113.77": "AS64500",
    "198.51.100.5": "AS13335", "198.51.100.6": "AS13335",
}


def fake_dns(domain):
    if domain not in DNS:
        return {"domain": domain, "status": "nxdomain", "A": [], "AAAA": [], "MX": [], "NS": []}
    return {"domain": domain, "status": "ok", "A": DNS[domain], "AAAA": [], "MX": [], "NS": []}


def fake_ip(ip):
    return {"ip": ip, "status": "ok", "asn": ASN.get(ip), "asn_description": "TEST",
            "country": "US", "network": None, "org": None}


def fake_rep(ip):
    return {"ip": ip, "status": "ok", "abuse_score": 0, "total_reports": 0}


def make_case(case_id, domains=(), ips=(), hashes=()):
    return EmailEvidence(
        case_id=case_id,
        iocs=IOCCollection(domains=list(domains), ips=list(ips)),
        attachments=[AttachmentEvidence("f.bin", "application/octet-stream", 1, h) for h in hashes],
    )


@patch("correlation.graph_builder.check_ip_reputation", fake_rep)
@patch("correlation.graph_builder.lookup_ip", fake_ip)
@patch("correlation.graph_builder.resolve_domain", fake_dns)
class CorrelationTests(unittest.TestCase):
    def setUp(self):
        service._master.clear()

    def related(self, a, b):
        service.enrich_evidence(a)
        out_b = service.enrich_evidence(b)
        return out_b.related_cases

    def test_shared_domain(self):
        rel = self.related(make_case("A", domains=["evil-one.test"]),
                           make_case("B", domains=["evil-one.test"]))
        self.assertEqual(rel[0].case_id, "A")
        self.assertEqual(rel[0].confidence, 0.7)

    def test_shared_ip_found_through_different_domains(self):
        rel = self.related(make_case("A", domains=["evil-one.test"]),
                           make_case("B", domains=["evil-two.test"]))
        self.assertIn("203.0.113.10", rel[0].all_shared)

    def test_shared_asn_is_weak(self):
        rel = self.related(make_case("A", domains=["evil-one.test"]),
                           make_case("B", domains=["other.test"]))
        self.assertEqual(rel[0].shared, "AS64500")
        self.assertEqual(rel[0].confidence, 0.2)

    def test_shared_hash_is_strongest(self):
        rel = self.related(make_case("A", hashes=["abc"]), make_case("B", hashes=["abc"]))
        self.assertEqual(rel[0].confidence, 0.9)

    def test_allowlisted_asn_creates_no_link(self):
        rel = self.related(make_case("A", domains=["big-site.test"]),
                           make_case("B", domains=["big-site-2.test"]))
        self.assertEqual(rel, [])

    def test_allowlisted_shared_ip_creates_no_link(self):
        rel = self.related(make_case("A", ips=["198.51.100.5"]),
                           make_case("B", ips=["198.51.100.5"]))
        self.assertEqual(rel, [])

    def test_unrelated_cases(self):
        rel = self.related(make_case("A", domains=["evil-one.test"]),
                           make_case("B", hashes=["zzz"]))
        self.assertEqual(rel, [])

    def test_earlier_case_learns_about_later_one(self):
        service.enrich_evidence(make_case("A", hashes=["abc"]))
        service.enrich_evidence(make_case("B", hashes=["abc"]))
        self.assertEqual(service.get_related_cases("A")[0].case_id, "B")

    def test_nonexistent_domain_is_scored_and_explained(self):
        _, out = build_case_graph(make_case("A", domains=["missing.test"]))
        entity = out.entities[0]
        self.assertEqual(entity.risk, 30)
        self.assertTrue(entity.risk_reasons)


class FailureTests(unittest.TestCase):
    def test_failed_lookup_does_not_crash_and_is_not_cached(self):
        calls = []

        @cached(ttl_seconds=60)
        def flaky(x):
            calls.append(x)
            return {"status": "timeout"} if len(calls) == 1 else {"status": "ok"}

        self.assertEqual(flaky("a")["status"], "timeout")
        self.assertEqual(flaky("a")["status"], "ok")      # retried, not stuck on the failure
        self.assertEqual(flaky("a")["status"], "ok")      # success is cached
        self.assertEqual(len(calls), 2)

    def test_slow_lookup_hits_time_budget(self):
        def slow(domain):
            time.sleep(2)
            return fake_dns(domain)

        with patch("correlation.graph_builder.resolve_domain", slow), \
             patch("correlation.graph_builder.lookup_ip", fake_ip), \
             patch("correlation.graph_builder.check_ip_reputation", fake_rep):
            start = time.monotonic()
            _, out = build_case_graph(make_case("A", domains=["evil-one.test"]), time_budget=0.3)
        self.assertLess(time.monotonic() - start, 1.5)
        self.assertEqual(out.entities[0].details["status"], "timeout")


class RiskRuleTests(unittest.TestCase):
    def test_risky_tld(self):
        score, reasons = score_domain("login-update.zip", {"status": "ok"})
        self.assertEqual(score, 15)

    def test_allowlisted_domain_scores_zero(self):
        self.assertEqual(score_domain("mail.google.com", {"status": "nxdomain"}), (0, []))


if __name__ == "__main__":
    unittest.main()
