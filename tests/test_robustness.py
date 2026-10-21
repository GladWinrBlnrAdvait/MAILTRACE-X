import base64
import json
import os
import tempfile
import time
import unittest
from dataclasses import asdict
from email.message import EmailMessage

from backend.detection import detect_phishing
from evidence.attachment_static import analyze_attachment_content
from evidence.email_parser import parse_email
from evidence.models import EmailEvidence

PDF_JS = (b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n"
          b"2 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\)) >>\nendobj\n")


def signal_ids(evidence):
    return [s["signal_id"] for s in evidence.evidence_signals]


def nested(depth, leaf):
    """Raw email with `depth` levels of multipart/mixed around `leaf`."""
    out = "From: a@example.com\nMIME-Version: 1.0\n"
    for i in range(depth):
        out += f'Content-Type: multipart/mixed; boundary="b{i}"\n\n--b{i}\n'
    out += leaf
    for i in reversed(range(depth)):
        out += f"\n--b{i}--\n"
    return out.encode()


PDF_LEAF = ("Content-Type: application/pdf; name=a.pdf\n"
            "Content-Disposition: attachment; filename=a.pdf\n"
            "Content-Transfer-Encoding: base64\n\n"
            + base64.b64encode(PDF_JS).decode())


class RobustnessCase(unittest.TestCase):

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def parse(self, data, name="mail.eml"):
        path = os.path.join(self.directory.name, name)
        with open(path, "wb") as handle:
            handle.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        evidence = parse_email(path, "T")
        self.assertIsInstance(evidence, EmailEvidence)
        # The API stores asdict(evidence) as JSON, so it must always serialize
        json.dumps(asdict(evidence), default=str)
        # ...and the detector must cope with whatever came out
        detect_phishing(evidence)
        return evidence


class TestMalformedEmails(RobustnessCase):

    CASES = {
        "empty": b"",
        "binary garbage": bytes(range(256)) * 20,
        "headers only": b"Subject: hi\r\n\r\n",
        "no headers at all": b"just a body with no headers\n",
        "duplicate From": b"From: a@a.com\nFrom: b@b.com\nSubject: x\n\nbody",
        "bad addresses": b"From: <<<@@@>>>\nTo: ,,,;;;\nReply-To: @@@\nSubject: x\n\nbody",
        "bad charset + base64": (b"From: a@a.com\nSubject: x\n"
                                 b"Content-Type: text/plain; charset=x-nonexistent\n"
                                 b"Content-Transfer-Encoding: base64\n\n////garbage!!\n"),
        "raw 8-bit header": "From: a@a.com\nSubject: caf\xe9 \xff\xfe\n\nbody".encode("latin-1"),
        "invalid RFC2047": b"From: a@a.com\nSubject: =?UTF-8?B?!!!notbase64?=\n\nbody",
        "NUL bytes": b"From: a@a.com\x00\nSubject: x\x00\n\nbo\x00dy",
        "huge single header": b"From: a@a.com\nSubject: " + b"A" * 2_000_000 + b"\n\nbody",
        "many headers": b"".join(b"X-H%d: v\n" % i for i in range(20000)) + b"\nbody",
    }

    def test_none_of_these_crash(self):
        for name, data in self.CASES.items():
            with self.subTest(case=name):
                self.parse(data)

    def test_missing_headers_are_reported_not_fatal(self):
        evidence = self.parse(b"Subject: only a subject\n\nbody")
        self.assertIsNone(evidence.metadata.sender)
        self.assertIn("HDR-006", signal_ids(evidence))
        self.assertEqual(evidence.received_hops, [])
        self.assertIsNone(evidence.origin_ip)


class TestNestedMime(RobustnessCase):

    def test_moderate_nesting_still_finds_the_attachment(self):
        evidence = self.parse(nested(30, PDF_LEAF))
        self.assertNotIn("PARSE-001", signal_ids(evidence))
        self.assertIn("ATT-006", signal_ids(evidence))

    def test_extreme_nesting_is_flagged_not_fatal(self):
        started = time.perf_counter()
        evidence = self.parse(nested(1500, PDF_LEAF))
        self.assertLess(time.perf_counter() - started, 15)
        self.assertIn("PARSE-001", signal_ids(evidence))

    def test_attached_email_is_inspected(self):
        inner = EmailMessage()
        inner["From"] = "x@example.org"
        inner["Subject"] = "inner"
        inner.set_content("inner body")
        inner.add_attachment(PDF_JS, maintype="application", subtype="pdf",
                             filename="inner.pdf")
        outer = EmailMessage()
        outer["From"] = "a@example.com"
        outer["To"] = "b@example.com"
        outer["Subject"] = "forwarded"
        outer.set_content("see attached")
        outer.add_attachment(inner)
        evidence = self.parse(bytes(outer))
        self.assertIn("ATT-006", signal_ids(evidence))


class TestOddEncodings(RobustnessCase):

    def message(self, charset, payload, transfer="base64"):
        if transfer == "base64":
            body = base64.b64encode(payload).decode()
        else:
            body = payload.decode("latin-1")
        return (f"From: a@example.com\nSubject: x\nMIME-Version: 1.0\n"
                f"Content-Type: text/plain; charset={charset}\n"
                f"Content-Transfer-Encoding: {transfer}\n\n{body}\n")

    def test_various_charsets(self):
        text = "Hello \u4f60\u597d \u3053\u3093\u306b\u3061\u306f https://example.org/x"
        cases = [
            ("shift_jis", text.encode("shift_jis", "ignore")),
            ("iso-2022-jp", text.encode("iso2022_jp", "ignore")),
            ("utf-16", text.encode("utf-16")),
            ("utf-8", b"\xef\xbb\xbf" + text.encode("utf-8")),
            ("utf-8", b"\xff\xfe invalid utf8 \xc3\x28"),
            ("x-unknown-charset", b"whatever"),
            ("us-ascii", b"caf\xe9 not ascii"),
        ]
        for charset, payload in cases:
            with self.subTest(charset=charset):
                evidence = self.parse(self.message(charset, payload))
                self.assertIsInstance(evidence.body.text, str)

    def test_quoted_printable_with_bad_escapes(self):
        evidence = self.parse(self.message("utf-8", b"bad =ZZ escape =\xe9 =", "quoted-printable"))
        self.assertIsInstance(evidence.body.text, str)

    def test_mixed_line_endings(self):
        raw = b"From: a@example.com\r\nSubject: x\nTo: b@example.com\r\n\nbody\r\nmore\nlines\r"
        self.assertEqual(self.parse(raw).metadata.sender, "a@example.com")


class TestAttachmentEdgeCases(RobustnessCase):

    def wrap(self, header_lines, payload=b"hello"):
        encoded = base64.b64encode(payload).decode()
        return (f"From: a@example.com\nMIME-Version: 1.0\n"
                f'Content-Type: multipart/mixed; boundary="B"\n\n--B\n'
                f"Content-Type: text/plain\n\nhi\n--B\n{header_lines}\n"
                f"Content-Transfer-Encoding: base64\n\n{encoded}\n--B--\n")

    def test_attachment_without_filename(self):
        evidence = self.parse(self.wrap("Content-Type: application/octet-stream\n"
                                        "Content-Disposition: attachment"))
        self.assertEqual(evidence.attachments[0].filename, "unnamed_attachment")

    def test_corrupt_base64_attachment(self):
        raw = ("From: a@example.com\nMIME-Version: 1.0\n"
               'Content-Type: multipart/mixed; boundary="B"\n\n--B\n'
               "Content-Type: application/pdf; name=a.pdf\n"
               "Content-Disposition: attachment; filename=a.pdf\n"
               "Content-Transfer-Encoding: base64\n\n@@@@not base64@@@@\n--B--\n")
        evidence = self.parse(raw)
        self.assertEqual(len(evidence.attachments), 1)

    def test_odd_filenames(self):
        names = ["..\\..\\evil.exe", "../../etc/passwd", "a" * 5000 + ".pdf",
                 "invoice\u202efdp.exe", "=?UTF-8?B?" + base64.b64encode("r\u00e9sum\u00e9.pdf".encode()).decode() + "?=",
                 "con.txt", "\x00null.exe"]
        for name in names:
            with self.subTest(name=name[:30]):
                self.parse(self.wrap(
                    f'Content-Type: application/octet-stream\nContent-Disposition: attachment; filename="{name}"'))

    def test_empty_attachment(self):
        evidence = self.parse(self.wrap("Content-Type: application/pdf\n"
                                        "Content-Disposition: attachment; filename=a.pdf", b""))
        self.assertEqual(evidence.attachments[0].size_bytes, 0)


class TestHostileInputIsFast(RobustnessCase):

    def test_large_pathological_bodies_parse_quickly(self):
        for name, filler in {"dotted": "a." * 500_000, "at signs": "a@" * 400_000,
                             "colons": ":a" * 400_000}.items():
            with self.subTest(body=name):
                started = time.perf_counter()
                self.parse("From: a@example.com\nSubject: x\n\n" + filler)
                self.assertLess(time.perf_counter() - started, 10)

    def test_pdf_with_endless_stream_markers_is_fast(self):
        for payload in (b"%PDF-1.4\n" + b"stream\n" * 700_000,
                        b"%PDF-1.4\n" + b"endstream\n" * 700_000,
                        b"%PDF-1.4\n" + b"stream\nendstream\n" * 300_000):
            started = time.perf_counter()
            analyze_attachment_content("a.pdf", payload)
            self.assertLess(time.perf_counter() - started, 5)

    def test_many_received_headers(self):
        raw = (b"".join(b"Received: from h%d.example.com (h%d [198.51.100.%d]) by x "
                        b"with SMTP; Tue, 13 Oct 2026 11:20:08 +0530\n" % (i, i, i % 250 + 1)
                        for i in range(800)) + b"From: a@example.com\n\nx")
        evidence = self.parse(raw)
        self.assertEqual(len(evidence.received_hops), 100)


class TestSampleCorpusTimeline(RobustnessCase):

    def test_brand_spoof_sample_exercises_every_new_feature(self):
        evidence = parse_email("samples/phishing_brand_spoof.eml", "T")
        ids = signal_ids(evidence)
        for expected in ("HDR-003", "HDR-005", "HDR-007"):
            self.assertIn(expected, ids)
        self.assertEqual(evidence.origin_ip, "2001:db8::25")
        self.assertIn("https://paypa1-secure.example.org/verify", evidence.iocs.urls)
        self.assertIn("helpdesk@paypa1-secure.example.org", evidence.iocs.emails)
        self.assertIn("2001:db8::25", evidence.iocs.ips)
        self.assertNotIn("10.0.0.7", evidence.iocs.ips)          # internal: filtered
        self.assertEqual(evidence.received_hops[0]["from_ip"], "10.0.0.7")  # but kept in the timeline

    def test_clean_corpus_emails_stay_clean(self):
        self.assertEqual(parse_email("samples/benign_newsletter.eml", "T").evidence_signals, [])


if __name__ == "__main__":
    unittest.main()
