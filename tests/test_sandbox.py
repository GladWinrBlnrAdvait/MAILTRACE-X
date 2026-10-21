import json
import os
import socket
import threading
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest import mock

from evidence import sandbox
from evidence.email_parser import parse_email
from evidence.models import AttachmentEvidence

EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def load_fixture(name):
    path = os.path.join("tests", "fixtures", name)
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


REPORT = load_fixture("vt_eicar_report.json")
BEHAVIOUR = load_fixture("vt_eicar_behaviour.json")


@contextmanager
def enabled():
    with mock.patch.dict(os.environ, {sandbox.PROVIDER_ENV: "virustotal",
                                      sandbox.KEY_ENV: "test-key"}):
        yield


@contextmanager
def disabled():
    with mock.patch.dict(os.environ, {}):
        os.environ.pop(sandbox.PROVIDER_ENV, None)
        os.environ.pop(sandbox.KEY_ENV, None)
        yield


def fake_api(routes):
    """
    Build a replacement for sandbox._get_json from {path_fragment: (code, data)}.
    The first fragment contained in the requested path wins, so list the more
    specific route (e.g. "behaviour_summary") before the generic one.
    """
    calls = []

    def _get_json(path, api_key, timeout=8):
        calls.append(path)
        for suffix, response in routes.items():
            if suffix in path:
                return response
        return 404, None

    _get_json.calls = calls
    return _get_json


class SandboxTestCase(unittest.TestCase):
    def setUp(self):
        sandbox._reset_state()


class TestSummarize(SandboxTestCase):

    def test_eicar_fixtures(self):
        summary = sandbox.summarize_vt_report(REPORT, BEHAVIOUR)
        self.assertEqual(summary["status"], "ok")
        self.assertEqual(summary["engines"]["malicious"], 66)
        self.assertEqual(summary["threat_label"], "virus.eicar/test")
        self.assertTrue(summary["behaviour"]["available"])
        self.assertEqual(summary["behaviour"]["sandboxes_total"], 4)
        self.assertEqual(summary["behaviour"]["sandboxes_non_clean"], 3)

    def test_techniques_ranked_by_severity_then_id(self):
        summary = sandbox.summarize_vt_report(REPORT, BEHAVIOUR)
        ids = [t["id"] for t in summary["techniques"]]
        self.assertEqual(ids, ["T1055", "T1497", "T1071"])
        self.assertEqual(summary["techniques"][0]["severity"], "low")
        self.assertEqual(summary["techniques"][2]["severity"], "unspecified")

    def test_none_inputs_mean_not_found(self):
        summary = sandbox.summarize_vt_report(None, None)
        self.assertEqual(summary["status"], "not_found")
        self.assertEqual(summary["engines"]["malicious"], 0)
        self.assertEqual(summary["techniques"], [])
        self.assertFalse(summary["behaviour"]["available"])

    def test_report_without_behaviour(self):
        summary = sandbox.summarize_vt_report(REPORT, None)
        self.assertEqual(summary["status"], "ok")
        self.assertFalse(summary["behaviour"]["available"])

    def test_survives_garbage_shapes(self):
        garbage = [
            {}, [], "text", 5,
            {"data": None}, {"data": {"attributes": "x"}},
            {"data": {"attributes": {"last_analysis_stats": [1, 2]}}},
            {"data": {"attributes": {"last_analysis_stats": {"malicious": "9"}}}},
            {"data": {"attributes": {"last_analysis_stats": {"malicious": -4}}}},
        ]
        weird_behaviour = [
            {"data": {"verdicts": [None, 3, "MALWARE"],
                      "mitre_attack_techniques": [None, "x", {"id": 5},
                                                  {"id": "not-an-id"},
                                                  {"id": "T1059"}]}},
            {"data": {"verdicts": "MALWARE", "mitre_attack_techniques": {}}},
        ]
        for report in garbage:
            for behaviour in [None] + garbage + weird_behaviour:
                summary = sandbox.summarize_vt_report(report, behaviour)
                self.assertIn("status", summary)
                self.assertGreaterEqual(summary["engines"]["malicious"], 0)

    def test_weird_behaviour_values_are_filtered(self):
        summary = sandbox.summarize_vt_report(None, {"data": {
            "verdicts": [None, 3, "malware", "clean"],
            "mitre_attack_techniques": [{"id": "not-an-id"}, {"id": "T1059"},
                                        {"id": "T1059.001"}],
        }})
        self.assertEqual(summary["behaviour"]["verdicts"], ["MALWARE", "CLEAN"])
        self.assertEqual(summary["behaviour"]["sandboxes_non_clean"], 1)
        self.assertEqual([t["id"] for t in summary["techniques"]],
                         ["T1059", "T1059.001"])

    def test_untrusted_text_is_cleaned_and_truncated(self):
        evil = "<script>alert(1)</script>\x00\x1b[31m" + "A" * 500
        summary = sandbox.summarize_vt_report(None, {"data": {
            "mitre_attack_techniques": [
                {"id": "T1059", "severity": "IMPACT_SEVERITY_HIGH",
                 "signature_description": evil}]}})
        description = summary["techniques"][0]["description"]
        self.assertLessEqual(len(description), sandbox.DESCRIPTION_LIMIT)
        self.assertNotIn("\x00", description)
        self.assertNotIn("\x1b", description)
        self.assertEqual(summary["techniques"][0]["severity"], "high")


class TestSignals(SandboxTestCase):

    def ids(self, summary):
        return [s["signal_id"] for s in
                sandbox.signals_from_summary("a.exe", EICAR, summary)]

    def test_eicar_summary_raises_all_three(self):
        summary = sandbox.summarize_vt_report(REPORT, BEHAVIOUR)
        signals = sandbox.signals_from_summary("a.exe", EICAR, summary)
        by_id = {s["signal_id"]: s for s in signals}
        self.assertEqual(set(by_id), {"SBX-001", "SBX-002", "SBX-003"})
        self.assertEqual(by_id["SBX-001"]["severity"], "high")
        self.assertEqual(by_id["SBX-002"]["severity"], "medium")
        self.assertEqual(by_id["SBX-003"]["severity"], "low")
        self.assertEqual(by_id["SBX-001"]["evidence"]["sha256"], EICAR)

    def test_engine_count_thresholds(self):
        expected = {0: None, 1: "low", 2: "low", 3: "medium",
                    9: "medium", 10: "high", 60: "high"}
        for count, severity in expected.items():
            summary = sandbox.summarize_vt_report(
                {"data": {"attributes": {
                    "last_analysis_stats": {"malicious": count}}}}, None)
            signals = sandbox.signals_from_summary("a", EICAR, summary)
            if severity is None:
                self.assertEqual(signals, [], count)
            else:
                self.assertEqual(signals[0]["severity"], severity, count)

    def test_sandbox_majority_rule(self):
        def summary(verdicts):
            return sandbox.summarize_vt_report(None, {"data": {"verdicts": verdicts}}) | {"status": "ok"}
        self.assertNotIn("SBX-002", self.ids(summary(["MALWARE", "CLEAN", "CLEAN"])))
        self.assertIn("SBX-002", self.ids(summary(["MALWARE", "CLEAN"])))
        self.assertIn("SBX-002", self.ids(summary(["MALWARE"])))

    def test_no_signals_unless_status_ok(self):
        for status in ("not_found", "disabled", "rate_limited", "unavailable"):
            self.assertEqual(
                sandbox.signals_from_summary("a", EICAR, {"status": status}), [])
        self.assertEqual(sandbox.signals_from_summary("a", EICAR, None), [])


class TestLookupHash(SandboxTestCase):

    def run_lookup(self, routes, sha=EICAR):
        api = fake_api(routes)
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            return sandbox.lookup_hash(sha), api

    def test_disabled_makes_no_calls(self):
        api = fake_api({})
        with disabled(), mock.patch.object(sandbox, "_get_json", api):
            self.assertEqual(sandbox.lookup_hash(EICAR), {"status": "disabled"})
        self.assertEqual(api.calls, [])

    def test_needs_both_variables(self):
        with mock.patch.dict(os.environ, {sandbox.KEY_ENV: "k"}):
            os.environ.pop(sandbox.PROVIDER_ENV, None)
            self.assertFalse(sandbox.is_enabled())
        with mock.patch.dict(os.environ, {sandbox.PROVIDER_ENV: "virustotal"}):
            os.environ.pop(sandbox.KEY_ENV, None)
            self.assertFalse(sandbox.is_enabled())

    def test_invalid_hash_rejected_without_call(self):
        for bad in ("", None, "zz", "../../etc/passwd", EICAR[:-1], EICAR + "0"):
            result, api = self.run_lookup({}, sha=bad)
            self.assertEqual(result, {"status": "invalid_hash"})
            self.assertEqual(api.calls, [])

    def test_not_found(self):
        result, api = self.run_lookup({EICAR: (404, None)})
        self.assertEqual(result["status"], "not_found")
        self.assertEqual(len(api.calls), 1)

    def test_found_with_behaviour(self):
        result, api = self.run_lookup({
            "behaviour_summary": (200, BEHAVIOUR),
            EICAR: (200, REPORT)})
        self.assertEqual(result["status"], "ok")
        self.assertTrue(result["behaviour"]["available"])
        self.assertEqual(len(api.calls), 2)

    def test_clean_file_skips_behaviour_call(self):
        clean = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 0, "suspicious": 0, "harmless": 60}}}}
        result, api = self.run_lookup({EICAR: (200, clean)})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(len(api.calls), 1)

    def test_behaviour_forbidden_keeps_report(self):
        result, _ = self.run_lookup({
            "behaviour_summary": (403, None), EICAR: (200, REPORT)})
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["behaviour"]["available"])
        self.assertEqual(result["engines"]["malicious"], 66)

    def test_error_statuses(self):
        cases = {401: "unauthorized", 403: "unauthorized", 429: "rate_limited",
                 500: "unavailable", 0: "unavailable"}
        for code, expected in cases.items():
            sandbox._reset_state()
            result, _ = self.run_lookup({EICAR: (code, None)})
            self.assertEqual(result["status"], expected, code)

    def test_200_with_bad_body_is_unavailable(self):
        result, _ = self.run_lookup({EICAR: (200, None)})
        self.assertEqual(result["status"], "unavailable")

    def test_results_are_cached_but_errors_are_not(self):
        api = fake_api({"behaviour_summary": (200, BEHAVIOUR), EICAR: (200, REPORT)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            sandbox.lookup_hash(EICAR)
            sandbox.lookup_hash(EICAR)
        self.assertEqual(len(api.calls), 2)   # second lookup came from cache

        sandbox._reset_state()
        api = fake_api({EICAR: (500, None)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            sandbox.lookup_hash(EICAR)
            sandbox.lookup_hash(EICAR)
        self.assertEqual(len(api.calls), 2)   # errors are retried

    def test_rate_limiter_blocks_the_fifth_call(self):
        api = fake_api({})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            hashes = [f"{i:064x}" for i in range(6)]
            statuses = [sandbox.lookup_hash(h)["status"] for h in hashes]
        self.assertEqual(statuses[:4], ["not_found"] * 4)
        self.assertEqual(statuses[4:], ["rate_limited"] * 2)
        self.assertEqual(len(api.calls), 4)

    def test_rate_limit_window_expires(self):
        with mock.patch.object(sandbox, "RATE_LIMIT_WINDOW", 0.05):
            for _ in range(4):
                self.assertTrue(sandbox._acquire_slot())
            self.assertFalse(sandbox._acquire_slot())
            time.sleep(0.08)
            self.assertTrue(sandbox._acquire_slot())


class TestEnrichAttachments(SandboxTestCase):

    def attachment(self, sha=EICAR, size=10, name="a.exe"):
        return AttachmentEvidence(filename=name, mime_type="x/y",
                                  size_bytes=size, sha256=sha)

    def test_disabled_leaves_attachments_untouched(self):
        attachment = self.attachment()
        with disabled():
            sandbox.enrich_attachments([attachment])
        self.assertIsNone(attachment.sandbox)
        self.assertEqual(attachment.signals, [])

    def test_enabled_adds_summary_and_signals(self):
        attachment = self.attachment()
        api = fake_api({"behaviour_summary": (200, BEHAVIOUR), EICAR: (200, REPORT)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            sandbox.enrich_attachments([attachment])
        self.assertEqual(attachment.sandbox["status"], "ok")
        self.assertEqual([s["signal_id"] for s in attachment.signals],
                         ["SBX-001", "SBX-002", "SBX-003"])

    def test_keeps_existing_static_signals(self):
        attachment = self.attachment()
        attachment.signals.append({"signal_id": "ATT-002"})
        api = fake_api({EICAR: (200, REPORT)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            sandbox.enrich_attachments([attachment])
        self.assertEqual(attachment.signals[0]["signal_id"], "ATT-002")
        self.assertIn("SBX-001", [s["signal_id"] for s in attachment.signals])

    def test_lookup_cap_and_empty_files_skipped(self):
        attachments = [self.attachment(sha=f"{i:064x}", name=f"f{i}") for i in range(1, 6)]
        attachments.insert(0, self.attachment(sha=f"{99:064x}", size=0))
        api = fake_api({})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            sandbox.enrich_attachments(attachments)
        self.assertEqual(len(api.calls), sandbox.MAX_LOOKUPS_PER_EMAIL)
        self.assertIsNone(attachments[0].sandbox)

    def test_unexpected_error_never_propagates(self):
        attachment = self.attachment()
        with enabled(), mock.patch.object(sandbox, "lookup_hash",
                                          side_effect=RuntimeError("boom")):
            sandbox.enrich_attachments([attachment])
        self.assertEqual(attachment.sandbox, {"status": "unavailable"})


class TestParserIntegration(SandboxTestCase):

    def test_disabled_by_default(self):
        with disabled():
            evidence = parse_email("samples/campaign_a_double_extension.eml", "T")
        ids = [s["signal_id"] for s in evidence.evidence_signals]
        self.assertIn("ATT-002", ids)
        self.assertFalse([i for i in ids if i.startswith("SBX")])

    def test_enabled_adds_sbx_to_evidence_signals(self):
        api = fake_api({"behaviour_summary": (200, BEHAVIOUR),
                        "/files/": (200, REPORT)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            evidence = parse_email("samples/campaign_a_double_extension.eml", "T")
        ids = [s["signal_id"] for s in evidence.evidence_signals]
        self.assertIn("ATT-002", ids)
        self.assertIn("SBX-001", ids)
        self.assertEqual(evidence.attachments[0].sandbox["status"], "ok")

    def test_api_down_does_not_break_parsing(self):
        api = fake_api({"/files/": (0, None)})
        with enabled(), mock.patch.object(sandbox, "_get_json", api):
            evidence = parse_email("samples/campaign_a_double_extension.eml", "T")
        self.assertEqual(evidence.attachments[0].sandbox["status"], "unavailable")
        self.assertIn("ATT-002", [s["signal_id"] for s in evidence.evidence_signals])


# --- the real HTTP function, against a local fake server --------------------

class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.requests.append((self.path, dict(self.headers)))
        if self.path == "/ok":
            self._send(200, b'{"hello": "world"}')
        elif self.path == "/forbidden":
            self._send(403, b'{"error": {"code": "ForbiddenError"}}')
        elif self.path == "/limited":
            self._send(429, b"{}")
        elif self.path == "/badjson":
            self._send(200, b"not json at all")
        elif self.path == "/slow":
            time.sleep(1.0)
            self._send(200, b"{}")
        else:
            self._send(404, b'{"error": {"code": "NotFoundError"}}')

    def _send(self, code, body):
        try:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception:
            pass


class TestRealHttpFunction(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.server.daemon_threads = True
        cls.server.requests = []
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def get(self, path, timeout=2):
        with mock.patch.object(sandbox, "API_BASE", self.base):
            return sandbox._get_json(path, "secret-key", timeout=timeout)

    def test_success_and_api_key_header(self):
        code, data = self.get("/ok")
        self.assertEqual((code, data), (200, {"hello": "world"}))
        headers = {k.lower(): v for k, v in self.server.requests[-1][1].items()}
        self.assertEqual(headers.get("x-apikey"), "secret-key")

    def test_http_error_statuses(self):
        self.assertEqual(self.get("/forbidden"), (403, None))
        self.assertEqual(self.get("/limited"), (429, None))
        self.assertEqual(self.get("/missing"), (404, None))

    def test_bad_json_is_a_failure_not_a_crash(self):
        self.assertEqual(self.get("/badjson"), (0, None))

    def test_timeout(self):
        self.assertEqual(self.get("/slow", timeout=0.2), (0, None))

    def test_connection_refused(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        with mock.patch.object(sandbox, "API_BASE", f"http://127.0.0.1:{port}"):
            self.assertEqual(sandbox._get_json("/x", "k", timeout=1), (0, None))


if __name__ == "__main__":
    unittest.main()
