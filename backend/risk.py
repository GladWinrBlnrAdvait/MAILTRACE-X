from backend.schemas import DetectionResult, RiskResult


SEVERITY_POINTS = {"critical": 20, "high": 15, "medium": 9, "low": 4}


def calculate_risk(evidence, detection: DetectionResult, correlation=None) -> RiskResult:
    """Combine ML, forensic evidence, and optional threat intelligence into one score."""
    score = round(detection.phishing_probability * 45)
    reasons = list(detection.reasons)
    for signal in evidence.evidence_signals:
        score += SEVERITY_POINTS.get(signal.get("severity", ""), 0)
        reasons.append(signal.get("description", "Security anomaly detected"))
    score += min(len(evidence.iocs.urls) * 3, 9)
    score += min(len(evidence.attachments) * 4, 8)
    if correlation:
        score += min(sum(entity.risk for entity in correlation.entities) // 8, 15)
        if correlation.related_cases:
            score += 8
            reasons.append("Infrastructure overlaps with an existing case")
    score = max(0, min(score, 100))
    level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    confidence = round(min(0.98, 0.45 + detection.phishing_probability * 0.35 + min(len(evidence.evidence_signals), 5) * 0.05), 2)
    return RiskResult(score=score, level=level, confidence=confidence, reasons=list(dict.fromkeys(reasons)))
