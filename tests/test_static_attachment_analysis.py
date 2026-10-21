import io
import os
import random
import unittest
import zipfile
import zlib

from evidence.attachment_static import (
    analyze_attachment_content,
    detect_file_type,
    get_extension,
    _summarize_macro_findings,
)
from evidence.email_parser import parse_email

PE_STUB = b"MZ harmless MAILTRACE-X test stub, not executable"
CLEAN_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"


def ids(signals):
    return [signal["signal_id"] for signal in signals]


def make_zip(entries, encrypted=False):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    raw = bytearray(buffer.getvalue())

    if encrypted:
        # zipfile cannot write encrypted entries (it clears the flag), so set
        # the "encrypted" general-purpose bit directly in the raw headers.
        for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            position = raw.find(signature)
            while position != -1:
                raw[position + offset] |= 0x1
                position = raw.find(signature, position + 4)

    return bytes(raw)


class TestFileTypeDetection(unittest.TestCase):

    def test_known_signatures(self):
        self.assertEqual(detect_file_type(CLEAN_PDF), "pdf")
        self.assertEqual(detect_file_type(PE_STUB), "pe")
        self.assertEqual(detect_file_type(b"\x7fELF\x02\x01"), "elf")
        self.assertEqual(detect_file_type(b"{\\rtf1\\ansi"), "rtf")
        self.assertEqual(detect_file_type(b"hello world"), "text")
        self.assertEqual(
            detect_file_type(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 8),
            "ole",
        )

    def test_zip_variants(self):
        self.assertEqual(detect_file_type(make_zip({"a.txt": b"x"})), "zip")
        self.assertEqual(
            detect_file_type(make_zip({"[Content_Types].xml": b"<x/>"})),
            "ooxml",
        )
        self.assertEqual(
            detect_file_type(make_zip({"META-INF/MANIFEST.MF": b"x"})),
            "jar",
        )

    def test_empty_and_unknown(self):
        self.assertIsNone(detect_file_type(b""))
        self.assertIsNone(detect_file_type(b"\x00\x01\x02\x03binary"))

    def test_extension_helper(self):
        self.assertEqual(get_extension("Invoice.PDF"), "pdf")
        self.assertEqual(get_extension("a.b.exe "), "exe")
        self.assertEqual(get_extension("noextension"), "")


class TestFilenameSignals(unittest.TestCase):

    def test_att001_extension_mismatch(self):
        _, signals = analyze_attachment_content("report.pdf", PE_STUB)
        self.assertEqual(ids(signals), ["ATT-001"])
        self.assertEqual(signals[0]["severity"], "high")
        self.assertEqual(signals[0]["evidence"]["detected_type"], "pe")

    def test_att001_medium_for_non_executable_mismatch(self):
        _, signals = analyze_attachment_content("report.pdf", b"<html>hi</html>")
        self.assertEqual(ids(signals), ["ATT-001"])
        self.assertEqual(signals[0]["severity"], "medium")

    def test_att002_double_extension(self):
        _, signals = analyze_attachment_content("invoice.pdf.exe", PE_STUB)
        self.assertEqual(ids(signals), ["ATT-002"])  # no duplicate ATT-003

    def test_att002_right_to_left_override(self):
        _, signals = analyze_attachment_content("invoice\u202efdp.exe", PE_STUB)
        self.assertIn("ATT-002", ids(signals))

    def test_att003_high_risk_extension(self):
        _, signals = analyze_attachment_content("update.js", b"var a = 1;")
        self.assertEqual(ids(signals), ["ATT-003"])

    def test_att003_executable_content_without_extension(self):
        _, signals = analyze_attachment_content("unnamed_attachment", PE_STUB)
        self.assertEqual(ids(signals), ["ATT-003"])

    def test_clean_files_raise_nothing(self):
        for name, data in [("notes.txt", b"plain text"),
                           ("report.pdf", CLEAN_PDF)]:
            _, signals = analyze_attachment_content(name, data)
            self.assertEqual(signals, [], name)


class TestPdfSignals(unittest.TestCase):

    def test_att006_and_att007(self):
        pdf = (b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n"
               b"2 0 obj\n<< /S /JavaScript /JS (app.alert\\(1\\)) >>\nendobj\n")
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertEqual(ids(signals), ["ATT-006", "ATT-007"])

    def test_att007_open_action_only(self):
        pdf = b"%PDF-1.4\n<< /OpenAction << /S /GoTo >> >>\n"
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertEqual(ids(signals), ["ATT-007"])

    def test_att008_launch(self):
        pdf = b"%PDF-1.4\n<< /S /Launch /F (cmd.exe) >>\n"
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertEqual(ids(signals), ["ATT-008"])

    def test_obfuscated_name_is_detected(self):
        pdf = b"%PDF-1.4\n<< /S /J#61vaScript /JS (x) >>\n"
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertIn("ATT-006", ids(signals))

    def test_javascript_inside_compressed_stream(self):
        hidden = zlib.compress(b"<< /S /JavaScript /JS (x) >>")
        pdf = (b"%PDF-1.5\n1 0 obj\n<< /Length 10 /Filter /FlateDecode >>\n"
               b"stream\n" + hidden + b"\nendstream\nendobj\n")
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertIn("ATT-006", ids(signals))

    def test_js_name_is_not_a_prefix_match(self):
        pdf = b"%PDF-1.4\n<< /JSX true /AAA true >>\n"
        _, signals = analyze_attachment_content("a.pdf", pdf)
        self.assertEqual(signals, [])


class TestMacroSignals(unittest.TestCase):

    def test_att004_from_sample_corpus(self):
        evidence = parse_email("samples/phishing_macro_invoice.eml", "T")
        self.assertIn("ATT-004", ids(evidence.evidence_signals))
        self.assertEqual(evidence.attachments[0].detected_type, "ooxml")

    def test_summarize_macro_findings_flags_autoexec(self):
        results = [
            ("AutoExec", "Document_Open", "runs on open"),
            ("Suspicious", "Shell", "runs commands"),
            ("Suspicious", "Shell", "dup"),
            ("IOC", "http://x", "url"),
        ]
        autoexec, suspicious = _summarize_macro_findings(results)
        self.assertEqual(autoexec, ["Document_Open"])
        self.assertEqual(suspicious, ["Shell"])

    def test_ooxml_without_macros_is_clean(self):
        data = make_zip({"[Content_Types].xml": b"<Types/>",
                         "word/document.xml": b"<w/>"})
        detected, signals = analyze_attachment_content("memo.docx", data)
        self.assertEqual(detected, "ooxml")
        self.assertEqual(signals, [])


class TestArchiveSignals(unittest.TestCase):

    def test_att009_archive_with_executable(self):
        data = make_zip({"readme.txt": b"hi", "setup.exe": PE_STUB})
        _, signals = analyze_attachment_content("files.zip", data)
        self.assertEqual(ids(signals), ["ATT-009"])
        self.assertIn("setup.exe", signals[0]["evidence"]["entries"])

    def test_att010_password_protected_archive(self):
        data = make_zip({"secret.docx": b"x"}, encrypted=True)
        _, signals = analyze_attachment_content("files.zip", data)
        self.assertIn("ATT-010", ids(signals))

    def test_clean_archive(self):
        data = make_zip({"a.txt": b"hello"})
        _, signals = analyze_attachment_content("files.zip", data)
        self.assertEqual(signals, [])


class TestRobustness(unittest.TestCase):

    def test_never_raises_on_hostile_input(self):
        rng = random.Random(1234)
        cases = [
            ("a.pdf", b""),
            ("a.pdf", b"%PDF-"),
            ("a.pdf", b"%PDF-1.4\nstream\nnot-zlib\nendstream"),
            ("a.zip", b"PK\x03\x04" + b"\x00" * 10),
            ("a.docx", b"PK\x03\x04truncated"),
            ("a.doc", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\xff" * 64),
            ("", b"MZ"),
            (None, b"data"),
            ("a.xlsm", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
        ]
        for _ in range(50):
            cases.append(("fuzz.bin", bytes(rng.getrandbits(8)
                                            for _ in range(rng.randint(0, 300)))))
        for name, data in cases:
            try:
                analyze_attachment_content(name, data)
            except Exception as error:  # pragma: no cover
                self.fail(f"raised {error!r} for {name!r}")

    def test_none_payload(self):
        detected, signals = analyze_attachment_content("a.txt", None)
        self.assertIsNone(detected)
        self.assertEqual(signals, [])


class TestSampleCorpusIntegration(unittest.TestCase):

    def parse(self, name):
        return parse_email(os.path.join("samples", name), "T")

    def test_benign_email_has_no_signals(self):
        self.assertEqual(self.parse("benign_newsletter.eml").evidence_signals, [])

    def test_campaign_a_double_extension(self):
        evidence = self.parse("campaign_a_double_extension.eml")
        self.assertIn("ATT-002", ids(evidence.evidence_signals))

    def test_campaign_b_open_action(self):
        evidence = self.parse("campaign_b_followup.eml")
        self.assertIn("ATT-007", ids(evidence.evidence_signals))

    def test_pdf_javascript_email(self):
        evidence = self.parse("phishing_pdf_javascript.eml")
        self.assertTrue({"ATT-006", "ATT-007"} <= set(ids(evidence.evidence_signals)))

    def test_campaign_emails_share_a_domain(self):
        a = self.parse("campaign_a_double_extension.eml")
        b = self.parse("campaign_b_followup.eml")
        self.assertIn("billing-update.example.org", set(a.iocs.domains) & set(b.iocs.domains))

    def test_attachment_signals_are_also_in_evidence_signals(self):
        evidence = self.parse("campaign_a_double_extension.eml")
        for signal in evidence.attachments[0].signals:
            self.assertIn(signal, evidence.evidence_signals)


if __name__ == "__main__":
    unittest.main()
