import unittest

from evidence.email_parser import parse_email


class TestAttachmentAnalyzer(unittest.TestCase):

    def test_attachment_extraction(self):

        evidence = parse_email(
            "samples/attachment_test.eml",
            "TEST-ATTACHMENT"
        )

        self.assertEqual(
            len(evidence.attachments),
            1
        )

        attachment = evidence.attachments[0]

        self.assertEqual(
            attachment.filename,
            "invoice.txt"
        )

        self.assertEqual(
            attachment.mime_type,
            "text/plain"
        )

        self.assertGreater(
            attachment.size_bytes,
            0
        )

        # SHA-256 hashes are always 64 hexadecimal characters
        self.assertEqual(
            len(attachment.sha256),
            64
        )


if __name__ == "__main__":
    unittest.main()