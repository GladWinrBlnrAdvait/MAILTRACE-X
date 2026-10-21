import time
import unittest

from evidence.ioc_extractor import extract_iocs, is_internal_ip, refang


class TestDefanging(unittest.TestCase):

    def test_hxxps_and_bracketed_dots(self):
        result = extract_iocs("Visit hxxps://evil[.]example[.]org/login now")
        self.assertIn("https://evil.example.org/login", result.urls)
        self.assertIn("evil.example.org", result.domains)

    def test_uppercase_and_bracketed_colon(self):
        result = extract_iocs("HXXP://x[.]example[.]net and hxxps[:]//a[.]example[.]org/p")
        self.assertIn("http://x.example.net", result.urls)
        self.assertIn("https://a.example.org/p", result.urls)

    def test_defanged_email_and_word_forms(self):
        result = extract_iocs("mail user[@]evil[.]example[.]org or admin(at)corp(dot)example(dot)net")
        self.assertIn("user@evil.example.org", result.emails)
        self.assertIn("admin@corp.example.net", result.emails)

    def test_defanged_ip(self):
        self.assertIn("8.8.8.8", extract_iocs("server 8[.]8[.]8[.]8 is bad").ips)

    def test_plain_text_is_left_alone(self):
        text = "See reference [1] and note (page 5); cost is $5."
        self.assertEqual(refang(text), text)


class TestIPv6(unittest.TestCase):

    def test_extracts_and_canonicalizes(self):
        result = extract_iocs("hosts 2001:DB8:0:0:0:0:0:1 and 2606:4700:4700::1111")
        self.assertIn("2001:db8::1", result.ips)
        self.assertIn("2606:4700:4700::1111", result.ips)

    def test_received_style_prefix_and_brackets(self):
        result = extract_iocs("from x (unknown [IPv6:2001:db8::2]) and [2001:db8::3] ok")
        self.assertIn("2001:db8::2", result.ips)
        self.assertIn("2001:db8::3", result.ips)

    def test_ipv6_in_url(self):
        result = extract_iocs("go http://[2001:db8::4]/x now")
        self.assertIn("2001:db8::4", result.ips)

    def test_times_and_mac_addresses_are_not_ipv6(self):
        result = extract_iocs("Date: Tue, 13 Oct 2026 11:20:08 +0530 at 12:30 mac aa:bb:cc:dd:ee:ff")
        self.assertEqual(result.ips, [])


class TestInternalFiltering(unittest.TestCase):

    def test_internal_addresses_are_dropped(self):
        internal = ["10.1.2.3", "192.168.1.1", "172.16.5.5", "172.31.255.1",
                    "127.0.0.1", "169.254.1.1", "0.0.0.0", "255.255.255.255",
                    "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1"]
        result = extract_iocs(" ".join(internal))
        self.assertEqual(result.ips, [])
        for value in internal:
            self.assertTrue(is_internal_ip(value), value)

    def test_public_and_documentation_addresses_are_kept(self):
        public = ["8.8.8.8", "1.1.1.1", "172.32.0.1", "100.128.0.1",
                  "192.0.2.50", "198.51.100.7", "203.0.113.9", "2001:db8::1"]
        result = extract_iocs(" ".join(public))
        for value in public:
            self.assertIn(value, result.ips)
            self.assertFalse(is_internal_ip(value), value)

    def test_is_internal_ip_on_garbage(self):
        for value in ("", "nope", "999.1.1.1", None):
            self.assertFalse(is_internal_ip(value))


class TestHostileInputIsFast(unittest.TestCase):
    """Regexes must not take quadratic time on adversarial text."""

    LIMIT_SECONDS = 5

    def timed(self, text):
        started = time.perf_counter()
        extract_iocs(text)
        return time.perf_counter() - started

    def test_pathological_strings(self):
        samples = {
            "dotted letters": "a." * 500_000,
            "long run": "a" * 3_000_000,
            "colon run": ":a" * 500_000,
            "at signs": "a@" * 500_000,
            "numeric dots": "1." * 500_000,
            "hex run": "A" * 2_000_000,
            "defang noise": "[.]" * 300_000,
        }
        for name, text in samples.items():
            elapsed = self.timed(text)
            self.assertLess(elapsed, self.LIMIT_SECONDS, f"{name}: {elapsed:.1f}s")


if __name__ == "__main__":
    unittest.main()
