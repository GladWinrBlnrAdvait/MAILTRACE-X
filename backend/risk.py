"""Deterministic, bounded composite risk scoring.

Formula: ``clamp(round(45 * model_probability) + signal_points +
unique_url_points + unique_attachment_points + correlation_points, 0, 100)``.
Signals are capped at 35, URLs at 9, attachments at 8, and correlation at 15.
Every collection is deduplicated by its stable identifier before scoring, so a
parser retry or repeated MIME part cannot inflate the result.
"""
from __future__ import annotations

from backend.schemas import DetectionResult, RiskResult


SEVERITY_POINTS = {"critical": 20, "high": 15, "medium": 9, "low": 4}


def _normalise(value: object) -> str:
    return " ".join(str(value or "").lower().split())


def _unique_signals(signals):
    seen, unique = set(), []
    for signal in signals:
        key = _normalise(signal.get("signal_id")) or _normalise(signal.get("description"))
        if key and key not in seen:
            seen.add(key)
            unique.append(signal)
    return unique


def calculate_risk(evidence, detection: DetectionResult, correlation=None) -> RiskResult:
    """Return a 0--100 risk result using a de-duplicated evidence ledger."""
    model_points = round(detection.phishing_probability * 45)
    signals = _unique_signals(evidence.evidence_signals)
    signal_points = min(sum(SEVERITY_POINTS.get(_normalise(s.get("severity")), 0) for s in signals), 35)
    urls = {_normalise(url) for url in evidence.iocs.urls if _normalise(url)}
    attachments = {getattr(item, "sha256", "") for item in evidence.attachments if getattr(item, "sha256", "")}
    url_points = min(len(urls) * 3, 9)
    attachment_points = min(len(attachments) * 4, 8)
    correlation_points, related_cases = 0, []
    if correlation:
        entity_risks = {}
        for entity in getattr(correlation, "entities", []):
            key = _normalise(getattr(entity, "entity_id", None) or getattr(entity, "value", None) or getattr(entity, "name", None))
            if key:
                entity_risks[key] = max(entity_risks.get(key, 0), getattr(entity, "risk", 0))
        correlation_points = min(sum(entity_risks.values()) // 8, 15)
        related_cases = list(getattr(correlation, "related_cases", []) or [])
        if related_cases:
            correlation_points = min(correlation_points + 8, 15)
    score = max(0, min(model_points + signal_points + url_points + attachment_points + correlation_points, 100))
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    confidence = round(min(0.98, 0.45 + detection.phishing_probability * 0.35 + min(len(signals), 5) * 0.05), 2)
    reasons = list(detection.reasons) + [s.get("description", "Security anomaly detected") for s in signals]
    if related_cases:
        reasons.append("Infrastructure overlaps with an existing case")
    return RiskResult(score=score, level=level, confidence=confidence, reasons=list(dict.fromkeys(reasons)))
