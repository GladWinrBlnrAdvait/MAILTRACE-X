from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class DetectionResult(BaseModel):
    classification: Literal["phishing", "suspicious", "legitimate"]
    phishing_probability: float = Field(ge=0, le=1)
    model: str
    features: dict[str, float]
    reasons: list[str] = []


class RiskResult(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["critical", "high", "medium", "low"]
    confidence: float = Field(ge=0, le=1)
    reasons: list[str] = []


class AnalysisResult(BaseModel):
    case_id: str
    created_at: datetime
    detection: DetectionResult
    risk: RiskResult
    evidence: dict
    correlation: dict | None = None


class CaseSummary(BaseModel):
    case_id: str
    created_at: datetime
    classification: str
    risk_score: int
    confidence: float
