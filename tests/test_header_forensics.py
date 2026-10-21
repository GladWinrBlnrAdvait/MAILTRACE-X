import unittest

from evidence.header_analyzer import analyze_headers
from evidence.models import EmailMetadata


def run(sender, message_id="<id@example.org>", **extra):
    metadata = EmailMetadata(sender=sender, message_id=message_id, **extra)
    return analyze_headers(metadata)


def ids(signals):
    return [signal["signal_id"] for signal in signals]


class TestDisplayNameSpoofing(unittest.TestCase):

    def test_hdr003_display_name_shows_other_address(self):
        signals = run('"support@paypal.com" <x@evil.example.org>')
        self.assertIn("HDR-003", ids(signals))
        signal = [s for s in signals if s["signal_id"] == "HDR-003"][0]
        self.assertEqual(signal["severity"], "high")
        self.assertEqual(signal["evidence"]["shown"], "support@paypal.com")
        self.assertEqual(signal["evidence"]["from_domain"], "evil.example.org")

    def test_hdr003_display_name_shows_other_domain(self):
        signals = run('"paypal.com Support" <x@evil.example.org>')
        signal = [s for s in signals if s["signal_id"] == "HDR-003"][0]
        self.assertEqual(signal["severity"], "medium")

    def test_same_or_related_domain_is_fine(self):
        for sender in ('"billing@acme.example.org" <noreply@acme.example.org>',
                       '"a@acme.example.org" <b@mail.acme.example.org>',
                       '"acme.example.org team" <b@acme.example.org>'):
            self.assertNotIn("HDR-003", ids(run(sender)), sender)

    def test_names_with_dots_are_not_domains(self):
        for sender in ('"Dr.Smith" <a@b.example.org>',
                       '"Mr.John Doe" <a@b.example.org>',
                       '"J.R.R. Tolkien" <a@b.example.org>'):
            self.assertNotIn("HDR-003", ids(run(sender)), sender)

    def test_hdr003_suppresses_hdr004(self):
        signals = ids(run('"PayPal support@paypal.com" <x@evil.example.org>'))
        self.assertIn("HDR-003", signals)
        self.assertNotIn("HDR-004", signals)


class TestBrandImpersonation(unittest.TestCase):

    def test_hdr004_brand_with_unrelated_domain(self):
        signals = run('"PayPal Support" <service@evil.example.org>')
        signal = [s for s in signals if s["signal_id"] == "HDR-004"][0]
        self.assertEqual(signal["severity"], "medium")
        self.assertEqual(signal["evidence"]["brand"], "paypal")

    def test_lookalike_suffix_is_not_the_brand(self):
        self.assertIn("HDR-004", ids(run('"PayPal" <a@notpaypal.com>')))

    def test_legitimate_brand_domains_are_fine(self):
        for sender in ('"PayPal" <service@paypal.com>',
                       '"PayPal" <a@mail.paypal.com>',
                       '"Microsoft Account Team" <x@accountprotection.microsoftonline.com>',
                       '"Amazon" <no-reply@amazon.in>'):
            self.assertNotIn("HDR-004", ids(run(sender)), sender)

    def test_brand_must_be_a_whole_word(self):
        self.assertNotIn("HDR-004", ids(run('"Pineapple Bakery" <a@b.example.org>')))
        self.assertNotIn("HDR-004", ids(run('"Applesauce Weekly" <a@b.example.org>')))

    def test_no_display_name_no_findings(self):
        self.assertEqual(
            [s for s in run("plain@example.org") if s["signal_id"] in ("HDR-003", "HDR-004")], [])


class TestMessageId(unittest.TestCase):

    def test_hdr005_unrelated_message_id_domain(self):
        signals = run("a@example.com", message_id="<abc@mailer.example.net>")
        signal = [s for s in signals if s["signal_id"] == "HDR-005"][0]
        self.assertEqual(signal["severity"], "low")
        self.assertEqual(signal["evidence"]["message_id_domain"], "mailer.example.net")

    def test_related_domains_are_fine(self):
        for sender, message_id in (
                ("a@example.com", "<x@example.com>"),
                ("a@example.com", "<x@mail.example.com>"),
                ("a@gmail.com", "<CAB123@mail.gmail.com>"),
                ("a@mail.example.com", "<x@example.com>")):
            self.assertNotIn("HDR-005", ids(run(sender, message_id=message_id)), message_id)

    def test_hdr006_missing_message_id(self):
        signals = ids(run("a@example.com", message_id=None))
        self.assertIn("HDR-006", signals)
        self.assertNotIn("HDR-005", signals)

    def test_present_message_id_has_no_hdr006(self):
        self.assertNotIn("HDR-006", ids(run("a@example.com", message_id="<x@example.com>")))


class TestWeirdInputs(unittest.TestCase):

    def test_never_raises(self):
        senders = [None, "", "<>", "@@@", "no address at all", '"" <>',
                   '"' + "A" * 10000 + '" <a@example.org>',
                   '"' + "a@" * 5000 + '" <a@example.org>',
                   "=?UTF-8?B?!!!?= <a@example.org>", "\x00\x01\x02 <a@b.c>"]
        message_ids = [None, "", "<>", "@", "<@>", " @ ", "x" * 5000,
                       "<" + "@" * 3000 + ">"]
        for sender in senders:
            for message_id in message_ids:
                analyze_headers(EmailMetadata(sender=sender, message_id=message_id,
                                              reply_to=sender, return_path=sender))


if __name__ == "__main__":
    unittest.main()
