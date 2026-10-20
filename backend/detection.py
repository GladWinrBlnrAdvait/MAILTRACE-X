"""Explainable NLP baseline for phishing detection.

The runtime has no hidden external service: it extracts stable text and evidence
features and applies a calibrated logistic score.  `ml/training/train_baseline.py`
can replace this baseline with a dataset-trained scikit-learn model later.
"""
from __future__ import annotations

import math
import re
from dataclasses import asdict
from pathlib import Path

from backend.schemas import DetectionResult

SUSPICIOUS_TERMS = {
    "urgent", "verify", "verification", "suspend", "suspended", "password",
    "account", "login", "invoice", "payment", "action required", "click here",
    "security alert", "limited time", "confirm",
}


def _logistic(value: float) -> float:
    return 1 / (1 + math.exp(-max(-20, min(20, value))))


def extract_features(evidence) -> tuple[dict[str, float], list[str]]:
    """Turn an EmailEvidence instance into deterministic, auditable features."""
    subject = (evidence.metadata.subject or "").lower()
    body = f"{evidence.body.text} {evidence.body.html}".lower()
    text = f"{subject} {body}"
    terms = sum(1 for term in SUSPICIOUS_TERMS if term in text)
    auth = evidence.authentication
    signals = evidence.evidence_signals
    reasons: list[str] = []

    features = {
        "suspicious_term_count": float(min(terms, 6)),
        "url_count": float(min(len(evidence.iocs.urls), 5)),
        "ip_count": float(min(len(evidence.iocs.ips), 5)),
        "attachment_count": float(min(len(evidence.attachments), 3)),
        "auth_failures": float(sum(value == "fail" for value in (auth.spf, auth.dkim, auth.dmarc))),
        "header_signal_count": float(min(len(signals), 5)),
        "reply_to_mismatch": float(any(signal.get("signal_id") == "HDR-001" for signal in signals)),
        "html_present": float(bool(evidence.body.html.strip())),
    }
    if terms:
        reasons.append("Urgency or credential-related language detected")
    if features["url_count"]:
        reasons.append("Email contains one or more URLs")
    if features["auth_failures"]:
        reasons.append("Email authentication checks failed")
    if features["reply_to_mismatch"]:
        reasons.append("Reply-To address differs from the sender")
    if features["attachment_count"]:
        reasons.append("Email contains an attachment")
    return features, reasons


def detect_phishing(evidence) -> DetectionResult:
    """Return an explainable baseline classification for a parsed email."""
    features, reasons = extract_features(evidence)
    trained_model = Path(__file__).resolve().parents[1] / "ml" / "models" / "phishing_baseline.joblib"
    model_name = "explainable-logistic-baseline-v1"
    if trained_model.exists():
        # The training script writes a Pipeline with predict_proba. Loading is
        # optional so production users can deploy only the lightweight baseline.
        import joblib
        text = " ".join(filter(None, [evidence.metadata.subject, evidence.body.text, evidence.body.html]))
        probability = round(float(joblib.load(trained_model).predict_proba([text])[0][1]), 4)
        model_name = "tfidf-logistic-regression-v1"
        reasons.insert(0, "Dataset-trained NLP model evaluated the email content")
    else:
        # Coefficients are intentionally documented and deterministic. They provide
        # a safe baseline until the team trains the supplied dataset pipeline.
        score = -3.0
        score += 0.34 * features["suspicious_term_count"]
        score += 0.40 * features["url_count"]
        score += 0.18 * features["ip_count"]
        score += 0.35 * features["attachment_count"]
        score += 1.05 * features["auth_failures"]
        score += 0.32 * features["header_signal_count"]
        score += 0.75 * features["reply_to_mismatch"]
        score += 0.15 * features["html_present"]
        probability = round(_logistic(score), 4)

    classification = "phishing" if probability >= 0.70 else "suspicious" if probability >= 0.35 else "legitimate"
    if classification == "legitimate" and not reasons:
        reasons.append("No strong phishing indicators found by the baseline")
    return DetectionResult(
        classification=classification,
        phishing_probability=probability,
        model=model_name,
        features=features,
        reasons=reasons,
    )
