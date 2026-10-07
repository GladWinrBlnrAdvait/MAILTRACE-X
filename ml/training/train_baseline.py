"""Train a reproducible TF-IDF + Logistic Regression phishing classifier.

Usage: python ml/training/train_baseline.py path/to/emails.csv
The CSV needs `text` and `label` columns, where label is 0 (legitimate) or 1 (phishing).
"""
import sys
def main(csv_path: str):
    # Imports stay inside the command entry point so API users who only need the
    # built-in baseline do not need the training toolchain at runtime.
    from pathlib import Path
    import joblib
    import pandas as pd
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import Pipeline
    data = pd.read_csv(csv_path).dropna(subset=["text", "label"])
    train, test = train_test_split(data, test_size=.2, random_state=42, stratify=data["label"])
    model = Pipeline([("tfidf", TfidfVectorizer(stop_words="english", ngram_range=(1, 2), max_features=25_000)), ("classifier", LogisticRegression(max_iter=2_000, class_weight="balanced"))])
    model.fit(train.text, train.label)
    print(classification_report(test.label, model.predict(test.text), digits=3))
    destination = Path(__file__).parents[1] / "models" / "phishing_baseline.joblib"
    destination.parent.mkdir(exist_ok=True)
    joblib.dump(model, destination)
    print(f"Saved trained model to {destination}")


if __name__ == "__main__":
    if len(sys.argv) != 2: raise SystemExit("Usage: train_baseline.py <emails.csv>")
    main(sys.argv[1])
