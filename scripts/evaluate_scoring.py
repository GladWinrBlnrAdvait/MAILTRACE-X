#!/usr/bin/env python3
"""Evaluate MAILTRACE-X against a labelled CSV: path,label (label is phishing/legitimate)."""
import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.detection import detect_phishing
from backend.risk import calculate_risk
from evidence.email_parser import parse_email


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="CSV containing path,label; paths are relative to the manifest")
    parser.add_argument("--output", default="scoring-evaluation.json")
    args = parser.parse_args()
    manifest = Path(args.manifest).resolve()
    rows = []
    with manifest.open(newline="", encoding="utf-8-sig") as stream:
        for index, item in enumerate(csv.DictReader(stream), start=1):
            label = item["label"].strip().lower()
            if label not in {"phishing", "legitimate"}:
                raise ValueError(f"Row {index}: label must be phishing or legitimate")
            email_path = (manifest.parent / item["path"]).resolve()
            evidence = parse_email(str(email_path), f"EVAL-{index:05d}")
            detection = detect_phishing(evidence)
            risk = calculate_risk(evidence, detection)
            rows.append({"path": item["path"], "label": label, "predicted": detection.classification,
                         "phishing_probability": detection.phishing_probability, "risk_score": risk.score,
                         "risk_level": risk.level, "saturated_100": risk.score == 100})
    if not rows:
        raise ValueError("The manifest contains no samples")
    actual = [r["label"] == "phishing" for r in rows]
    predicted = [r["predicted"] == "phishing" for r in rows]
    tp = sum(a and p for a, p in zip(actual, predicted))
    fp = sum((not a) and p for a, p in zip(actual, predicted))
    fn = sum(a and (not p) for a, p in zip(actual, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    phishing_scores = [r["risk_score"] for r in rows if r["label"] == "phishing"]
    legitimate_scores = [r["risk_score"] for r in rows if r["label"] == "legitimate"]
    report = {"sample_count": len(rows), "confusion": {"true_positive": tp, "false_positive": fp,
              "false_negative": fn, "true_negative": sum((not a) and (not p) for a, p in zip(actual, predicted))},
              "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
              "risk_score_summary": {"phishing_count": len(phishing_scores), "phishing_mean": round(sum(phishing_scores)/len(phishing_scores), 2) if phishing_scores else None,
              "phishing_min": min(phishing_scores) if phishing_scores else None, "phishing_max": max(phishing_scores) if phishing_scores else None,
              "legitimate_count": len(legitimate_scores), "legitimate_mean": round(sum(legitimate_scores)/len(legitimate_scores), 2) if legitimate_scores else None,
              "legitimate_min": min(legitimate_scores) if legitimate_scores else None, "legitimate_max": max(legitimate_scores) if legitimate_scores else None,
              "score_100_count": sum(r["saturated_100"] for r in rows)}, "samples": rows}
    Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k != "samples"}, indent=2))
    print(f"Detailed report: {args.output}")


if __name__ == "__main__":
    main()
