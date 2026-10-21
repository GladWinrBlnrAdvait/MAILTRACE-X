"""Dependency-free regression checks for dashboard XSS and API-key URLs.

These checks do not replace a real browser test, but they run without Playwright
or Chromium and catch common regressions in CI/offline environments.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestDashboardStaticSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app_js = (ROOT / "dashboard" / "app.js").read_text(encoding="utf-8")

    def test_attacker_controlled_values_are_escaped_before_html_insertion(self):
        self.assertIn("function escapeHtml(value)", self.app_js)
        self.assertIn("d.textContent = value", self.app_js)
        # All attacker-controlled fields interpolated into HTML must be escaped.
        for expression in ("escapeHtml(r)", "escapeHtml(key)", "escapeHtml(value)",
                           "escapeHtml(i)", "escapeHtml(a.filename)",
                           "escapeHtml(a.mime_type)", "escapeHtml(a.sha256)",
                           "escapeHtml(term)"):
            self.assertIn(expression, self.app_js, f"Missing escaping for {expression}")

    def test_report_urls_do_not_include_api_key_query_parameter(self):
        self.assertNotRegex(self.app_js, re.compile(r"[?&]api_key\s*="))
        self.assertIn("headers: {'X-API-Key': apiKey}", self.app_js)


if __name__ == "__main__":
    unittest.main()
