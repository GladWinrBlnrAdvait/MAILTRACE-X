"""Real Chromium dashboard XSS smoke test. Install with `pip install -r requirements-dev.txt` and `playwright install chromium`."""
import json
import unittest
from pathlib import Path

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    sync_playwright = None

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipIf(sync_playwright is None, "Install requirements-dev.txt for browser XSS test")
class TestDashboardBrowser(unittest.TestCase):
    def test_attacker_controlled_authentication_keys_render_as_text(self):
        with sync_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).exists():
                self.skipTest("Chromium is not installed; run `playwright install chromium`")
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            payload_text = '<img src=x onerror="window.__xss=1">'
            result = {
                "case_id": "CASE-TEST1234",
                "created_at": "2026-01-01T00:00:00Z",
                "risk": {"score": 80, "level": "critical", "confidence": 0.9, "reasons": [payload_text]},
                "detection": {"classification": "phishing", "phishing_probability": 0.98, "term_contributions": {payload_text: 0.4}},
                "evidence": {
                    "authentication": {payload_text: payload_text, "spf": "fail"},
                    "iocs": {"urls": [payload_text], "domains": [], "ips": [], "emails": []},
                    "attachments": [{"filename": payload_text, "mime_type": "text/plain", "sha256": "abc"}],
                },
                "correlation": {"related_cases": []},
            }
            page.route("**/api/analyze/email", lambda route: route.fulfill(
                status=200, content_type="application/json", body=json.dumps(result)))
            page.set_content((ROOT / "dashboard/index.html").read_text(encoding="utf-8"))
            page.add_script_tag(path=str(ROOT / "dashboard/app.js"))
            page.locator("#api-key").fill("browser-test-secret")
            page.locator("#login-form button[type=submit]").click()
            page.locator("#email-file").set_input_files(str(ROOT / "samples/sample.eml"))
            page.locator("#upload-form button[type=submit]").click()
            page.wait_for_selector("#results:not([hidden])")
            self.assertEqual(page.locator("#auth img, #reasons img, #iocs img, #attachments img, #terms img").count(), 0)
            self.assertEqual(page.evaluate("window.__xss || 0"), 0)
            self.assertNotIn("api_key=", page.locator("#report-link").get_attribute("href"))
            self.assertNotIn("api_key=", page.locator("#pdf-link").get_attribute("href"))
            self.assertIn("&lt;IMG", page.locator("#auth").inner_html())
            browser.close()


if __name__ == "__main__":
    unittest.main()
