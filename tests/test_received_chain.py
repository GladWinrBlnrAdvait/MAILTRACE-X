import unittest

from evidence.received_chain import (MAX_HOPS, analyze_received_chain,
                                     parse_received_chain)

# newest first, exactly as they appear in a real message
HEADERS = [
    "from relay2.example.org (relay2.example.org [198.51.100.60]) "
    "by mx.example.net with ESMTPS; Sat, 17 Oct 2026 10:00:20 +0530",
    "from app.example.org (unknown [IPv6:2001:db8::25]) "
    "by relay2.example.org with SMTP; Sat, 17 Oct 2026 10:00:05 +0530",
    "from [10.0.0.7] (helo=localhost) by app.example.org "
    "with ESMTP; Sat, 17 Oct 2026 10:00:00 +0530",
]


class TestParsing(unittest.TestCase):

    def test_chronological_order_and_numbering(self):
        hops, _ = parse_received_chain(HEADERS)
        self.assertEqual([h["hop"] for h in hops], [1, 2, 3])
        self.assertEqual(hops[0]["by_host"], "app.example.org")
        self.assertEqual(hops[2]["by_host"], "mx.example.net")

    def test_fields(self):
        hops, _ = parse_received_chain(HEADERS)
        self.assertEqual(hops[2]["from_host"], "relay2.example.org")
        self.assertEqual(hops[2]["from_ip"], "198.51.100.60")
        self.assertEqual(hops[2]["protocol"], "ESMTPS")
        self.assertEqual(hops[2]["timestamp"], "2026-10-17T10:00:20+05:30")

    def test_ipv6_with_prefix_and_bracket_only_host(self):
        hops, _ = parse_received_chain(HEADERS)
        self.assertEqual(hops[1]["from_ip"], "2001:db8::25")
        self.assertEqual(hops[0]["from_ip"], "10.0.0.7")

    def test_delays(self):
        hops, _ = parse_received_chain(HEADERS)
        self.assertIsNone(hops[0]["delay_seconds"])
        self.assertEqual(hops[1]["delay_seconds"], 5)
        self.assertEqual(hops[2]["delay_seconds"], 15)

    def test_folded_header(self):
        folded = ("from mail.example.com (mail.example.com\r\n\t[192.0.2.10])\r\n"
                  "\tby mx.example.net with ESMTPS\r\n\t; Mon, 12 Oct 2026 09:00:05 +0530")
        hops, origin = parse_received_chain([folded])
        self.assertEqual(hops[0]["from_host"], "mail.example.com")
        self.assertEqual(hops[0]["from_ip"], "192.0.2.10")
        self.assertEqual(origin, "192.0.2.10")

    def test_empty_inputs(self):
        for value in (None, [], ()):
            self.assertEqual(parse_received_chain(value), ([], None))


class TestOriginIp(unittest.TestCase):

    def test_skips_internal_hops(self):
        _, origin = parse_received_chain(HEADERS)
        self.assertEqual(origin, "2001:db8::25")   # hop 1 is 10.0.0.7 (internal)

    def test_none_when_only_internal(self):
        _, origin = parse_received_chain(
            ["from a (a [192.168.1.5]) by b with SMTP; Sat, 17 Oct 2026 10:00:00 +0530"])
        self.assertIsNone(origin)


class TestOutOfOrderSignal(unittest.TestCase):

    def make(self, later, earlier):
        return [f"from b (b [198.51.100.2]) by c with SMTP; {earlier}",
                f"from a (a [198.51.100.1]) by b with SMTP; {later}"]

    def test_hdr007_when_time_goes_backwards(self):
        hops, _ = parse_received_chain(self.make(
            "Sat, 17 Oct 2026 10:00:00 +0530", "Sat, 17 Oct 2026 09:30:00 +0530"))
        signals = analyze_received_chain(hops)
        self.assertEqual([s["signal_id"] for s in signals], ["HDR-007"])
        self.assertEqual(signals[0]["evidence"]["hops"][0]["delay_seconds"], -1800)

    def test_small_skew_is_tolerated(self):
        hops, _ = parse_received_chain(self.make(
            "Sat, 17 Oct 2026 10:00:00 +0530", "Sat, 17 Oct 2026 09:59:00 +0530"))
        self.assertEqual(analyze_received_chain(hops), [])

    def test_in_order_chain_is_clean(self):
        hops, _ = parse_received_chain(HEADERS)
        self.assertEqual(analyze_received_chain(hops), [])

    def test_mixed_naive_and_aware_timestamps_do_not_crash(self):
        hops, _ = parse_received_chain(self.make(
            "Sat, 17 Oct 2026 10:00:00 -0000", "Sat, 17 Oct 2026 10:00:10 +0530"))
        self.assertIsNone(hops[1]["delay_seconds"])
        self.assertEqual(analyze_received_chain(hops), [])


class TestMalformed(unittest.TestCase):

    def test_garbage_headers(self):
        garbage = ["", "not a received header", ";;;;", "by", "from",
                   "from x by y with z; not a date", "\x00\x01 from \x02",
                   "X" * 100000, "from " + "a" * 5000 + " by b"]
        hops, origin = parse_received_chain(garbage)
        self.assertEqual(len(hops), len(garbage))
        analyze_received_chain(hops)

    def test_control_characters_are_cleaned(self):
        hops, _ = parse_received_chain(["from ev\x00il\x1b[31m.example.org by x; Sat, 17 Oct 2026 10:00:00 +0530"])
        self.assertNotIn("\x00", hops[0]["from_host"])
        self.assertNotIn("\x1b", hops[0]["from_host"])

    def test_field_length_is_capped(self):
        hops, _ = parse_received_chain(["from " + "a" * 5000 + " by b"])
        self.assertLessEqual(len(hops[0]["from_host"]), 255)

    def test_hop_cap_keeps_the_oldest(self):
        headers = [f"from h{i} (h{i} [198.51.100.{i % 250 + 1}]) by x with SMTP" for i in range(800)]
        hops, _ = parse_received_chain(headers)
        self.assertEqual(len(hops), MAX_HOPS)
        self.assertEqual(hops[0]["from_host"], "h799")   # last header = oldest hop


if __name__ == "__main__":
    unittest.main()
