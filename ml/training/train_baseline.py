"""Train and evaluate phishing detection on a held-out labelled CSV.

Usage: ``python ml/training/train_baseline.py emails.csv``. The CSV requires
``text`` and binary ``label`` columns. Metrics are stored with the model.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

SUSPICIOUS_TERMS = {"urgent", "verify", "verification", "suspend", "password", "account", "login", "invoice", "payment", "click here", "confirm"}


def lexical_baseline_predictions(texts):
    """The former transparent lexical baseline, retained for comparison."""
    return [int(sum(term in str(text).lower() for term in SUSPICIOUS_TERMS) >= 2) for text in texts]


def metrics_for(y_true, y_pred):
    from sklearn.metrics import confusion_matrix, f1_score, precision_score, recall_score
    tn, fp, _, _ = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"precision": round(float(precision_score(y_true, y_pred, zero_division=0)), 4), "recall": round(float(recall_score(y_true, y_pred, zero_division=0)), 4), "f1": round(float(f1_score(y_true, y_pred, zero_division=0)), 4), "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4)}


def main(csv_path: str):
    import joblib
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    data = pd.read_csv(csv_path).dropna(subset=["text", "label"])
    if set(data.label.unique()) - {0, 1} or data.label.nunique() != 2:
        raise ValueError("label must contain both binary classes 0 and 1")
    train, test = train_test_split(data, test_size=.2, random_state=42, stratify=data["label"])
    model = Pipeline([("tfidf", TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=25_000)), ("classifier", LogisticRegression(max_iter=2_000, class_weight="balanced", random_state=42))])
    model.fit(train.text, train.label)
    evaluation = {"dataset": str(Path(csv_path).name), "held_out_rows": int(len(test)), "baseline": metrics_for(test.label, lexical_baseline_predictions(test.text)), "tfidf_logistic_regression": metrics_for(test.label, model.predict(test.text))}
    destination = Path(__file__).parents[1] / "models"
    destination.mkdir(exist_ok=True)
    joblib.dump(model, destination / "phishing_baseline.joblib")
    (destination / "evaluation.json").write_text(json.dumps(evaluation, indent=2), encoding="utf-8")
    print(json.dumps(evaluation, indent=2))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: train_baseline.py <emails.csv>")
    main(sys.argv[1])
