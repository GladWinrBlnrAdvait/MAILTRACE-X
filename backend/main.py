from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from backend.detection import detect_phishing
from backend.repository import CaseRepository
from backend.reporting import build_html_report
from backend.risk import calculate_risk
from backend.schemas import AnalysisResult, CaseSummary
from correlation.service import enrich_evidence
from evidence.email_parser import parse_email

ROOT = Path(__file__).resolve().parents[1]
app = FastAPI(title="MAILTRACE-X API", version="1.0.0", description="Explainable phishing investigation platform")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.mount("/dashboard", StaticFiles(directory=ROOT / "dashboard", html=True), name="dashboard")
repository = CaseRepository(ROOT / "mailtrace.db")


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "MAILTRACE-X"}


@app.post("/api/analyze/email", response_model=AnalysisResult)
async def analyze_email(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith(".eml"):
        raise HTTPException(415, "Upload an .eml email file.")
    content = await file.read()
    if not content:
        raise HTTPException(422, "The uploaded email is empty.")
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(413, "Email exceeds the 10 MB prototype limit.")
    case_id = f"CASE-{uuid4().hex[:8].upper()}"
    with NamedTemporaryFile(suffix=".eml", delete=False) as temporary:
        temporary.write(content)
        temporary_path = temporary.name
    try:
        evidence = parse_email(temporary_path, case_id)
    finally:
        Path(temporary_path).unlink(missing_ok=True)
    detection = detect_phishing(evidence)
    correlation = enrich_evidence(evidence)
    risk = calculate_risk(evidence, detection, correlation)
    result = AnalysisResult(case_id=case_id, created_at=datetime.now(timezone.utc), detection=detection, risk=risk, evidence=asdict(evidence), correlation=correlation.model_dump())
    payload = result.model_dump(mode="json")
    repository.save(payload)
    return payload


@app.get("/api/cases", response_model=list[CaseSummary])
def list_cases():
    return repository.list()


@app.get("/api/case/{case_id}", response_model=AnalysisResult)
def get_case(case_id: str):
    result = repository.get(case_id)
    if not result:
        raise HTTPException(404, "Case not found.")
    return result


@app.get("/api/report/{case_id}", response_class=HTMLResponse)
def get_report(case_id: str):
    result = repository.get(case_id)
    if not result:
        raise HTTPException(404, "Case not found.")
    return build_html_report(result)
