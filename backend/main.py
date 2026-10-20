from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4
import os
import secrets

from fastapi import Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.detection import detect_phishing
from backend.repository import CaseRepository
from backend.reporting import build_html_report, build_pdf_report
from backend.risk import calculate_risk
from backend.schemas import AnalysisResult, CaseSummary
from correlation.export import export_graph
from correlation.service import enrich_evidence, get_related_cases, load_cases
from evidence.email_parser import parse_email

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="MAILTRACE-X API", version="1.0.0", description="Explainable phishing investigation platform")
allowed_origins = [origin.strip() for origin in os.getenv("MAILTRACE_ALLOWED_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000").split(",") if origin.strip()]
app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_methods=["GET", "POST"], allow_headers=["X-API-Key", "Content-Type"])
app.mount("/dashboard", StaticFiles(directory=ROOT / "dashboard", html=True), name="dashboard")
repository = CaseRepository(ROOT / "mailtrace.db")
# Rebuild the correlation graph from saved cases so related-case links survive a restart
load_cases(repository.get(case["case_id"]) for case in repository.list())


def api_error(status: int, code: str, message: str):
    raise HTTPException(status, {"code": code, "message": message})


def require_api_key(x_api_key: str | None = Query(default=None, alias="api_key"), header_key: str | None = Header(default=None, alias="X-API-Key")):
    """Protect case data with an environment-managed API key.

    ``MAILTRACE_API_KEY`` must be set in deployed environments. The explicit
    development value keeps the sample usable locally and is never suitable for
    a public deployment.
    """
    configured = os.getenv("MAILTRACE_API_KEY", "mailtrace-dev-key")
    supplied = header_key or x_api_key
    if not supplied or not secrets.compare_digest(supplied, configured):
        api_error(401, "authentication_required", "A valid X-API-Key is required.")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MAILTRACE-X"}


@app.post("/api/analyze/email", response_model=AnalysisResult)
async def analyze_email(file: UploadFile = File(...), _: None = Depends(require_api_key)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        api_error(415, "invalid_file_type", "Upload an .eml email file.")
    content = await file.read()
    if not content:
        api_error(422, "empty_upload", "The uploaded email is empty.")
    if len(content) > 10 * 1024 * 1024:
        api_error(413, "upload_too_large", "Email exceeds the 10 MB prototype limit.")
    case_id = f"CASE-{uuid4().hex[:8].upper()}"
    with NamedTemporaryFile(suffix=".eml", delete=False) as temporary:
        temporary.write(content)
        temporary_path = temporary.name
    try:
        try:
            evidence = parse_email(temporary_path, case_id)
        except Exception as error:
            api_error(422, "email_parse_failed", f"The email could not be parsed: {error}")
    finally:
        Path(temporary_path).unlink(missing_ok=True)
    try:
        detection = detect_phishing(evidence)
    except Exception:
        api_error(503, "detection_unavailable", "The detection component is temporarily unavailable.")
    try:
        correlation = await run_in_threadpool(enrich_evidence, evidence)
    except Exception:
        api_error(503, "correlation_unavailable", "The correlation component is temporarily unavailable.")
    risk = calculate_risk(evidence, detection, correlation)
    result = AnalysisResult(case_id=case_id, created_at=datetime.now(timezone.utc), detection=detection, risk=risk, evidence=asdict(evidence), correlation=correlation.model_dump())
    payload = result.model_dump(mode="json")
    try:
        repository.save(payload)
    except Exception:
        api_error(503, "persistence_unavailable", "The case could not be saved. Please retry.")
    return payload


@app.get("/api/cases", response_model=list[CaseSummary])
def list_cases(_: None = Depends(require_api_key)):
    return repository.list()


@app.get("/api/case/{case_id}", response_model=AnalysisResult)
def get_case(case_id: str, _: None = Depends(require_api_key)):
    result = repository.get(case_id)
    if not result:
        api_error(404, "case_not_found", "Case not found.")
    if result.get("correlation"):   # related cases may have appeared after this case was saved
        result["correlation"]["related_cases"] = [r.model_dump() for r in get_related_cases(case_id)]
    return result


@app.get("/api/case/{case_id}/graph")
def get_case_graph(case_id: str, _: None = Depends(require_api_key)):
    """Nodes-and-edges JSON of a case's evidence graph, for the dashboard."""
    result = get_case(case_id)   # reuses the 404 check and the refreshed related cases
    if not result.get("correlation"):
        api_error(404, "correlation_not_found", "No correlation data for this case.")
    return export_graph(result["correlation"])


@app.get("/api/report/{case_id}", response_class=HTMLResponse)
def get_report(case_id: str, _: None = Depends(require_api_key)):
    result = repository.get(case_id)
    if not result:
        api_error(404, "case_not_found", "Case not found.")
    return build_html_report(result)


@app.get("/api/report/{case_id}/pdf")
def get_pdf_report(case_id: str, _: None = Depends(require_api_key)):
    """Download a concise, shareable PDF report for an authenticated case."""
    from fastapi.responses import Response
    result = repository.get(case_id)
    if not result:
        api_error(404, "case_not_found", "Case not found.")
    return Response(build_pdf_report(result), media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="{case_id}-report.pdf"'})
