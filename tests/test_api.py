import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.main import app
from correlation.models import CorrelatedThreatData


class TestAPI(unittest.TestCase):
    headers = {"X-API-Key": "mailtrace-dev-key"}

    def setUp(self):
        self.client = TestClient(app)

    def test_authentication_is_required(self):
        self.assertEqual(self.client.get("/api/cases").status_code, 401)

    def test_all_case_endpoints(self):
        with patch("backend.main.enrich_evidence", side_effect=lambda evidence: CorrelatedThreatData(case_id=evidence.case_id)):
            health = self.client.get("/api/health")
            self.assertEqual(health.status_code, 200)
            with open("samples/sample.eml", "rb") as email:
                response = self.client.post("/api/analyze/email", headers=self.headers, files={"file": ("sample.eml", email, "message/rfc822")})
        self.assertEqual(response.status_code, 200, response.text)
        case_id = response.json()["case_id"]
        self.assertEqual(self.client.get("/api/cases", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/case/{case_id}", headers=self.headers).status_code, 200)
        self.assertEqual(self.client.get(f"/api/case/{case_id}/graph", headers=self.headers).status_code, 200)
        report = self.client.get(f"/api/report/{case_id}", headers=self.headers)
        self.assertEqual(report.status_code, 200)
        self.assertIn("Authentication results", report.text)
        pdf = self.client.get(f"/api/report/{case_id}/pdf", headers=self.headers)
        self.assertEqual(pdf.status_code, 200)
        self.assertEqual(pdf.headers["content-type"], "application/pdf")

    def test_invalid_upload_and_component_failure_have_clean_errors(self):
        bad = self.client.post("/api/analyze/email", headers=self.headers, files={"file": ("bad.txt", b"x", "text/plain")})
        self.assertEqual(bad.status_code, 415)
        self.assertEqual(bad.json()["detail"]["code"], "invalid_file_type")
        with patch("backend.main.detect_phishing", side_effect=RuntimeError("offline")):
            with open("samples/sample.eml", "rb") as email:
                failed = self.client.post("/api/analyze/email", headers=self.headers, files={"file": ("sample.eml", email)})
        self.assertEqual(failed.status_code, 503)
        self.assertEqual(failed.json()["detail"]["code"], "detection_unavailable")


if __name__ == "__main__":
    unittest.main()
