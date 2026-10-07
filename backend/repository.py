import json
import sqlite3
from pathlib import Path


class CaseRepository:
    """Small local SQLite store; keeps the prototype usable without cloud setup."""
    def __init__(self, database_path: str = "mailtrace.db"):
        self.database_path = Path(database_path)
        self._initialise()

    def _connect(self):
        return sqlite3.connect(self.database_path)

    def _initialise(self):
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS cases (
                case_id TEXT PRIMARY KEY, created_at TEXT NOT NULL,
                classification TEXT NOT NULL, risk_score INTEGER NOT NULL,
                confidence REAL NOT NULL, payload TEXT NOT NULL
            )""")

    def save(self, result: dict):
        with self._connect() as connection:
            connection.execute("""INSERT OR REPLACE INTO cases
                (case_id, created_at, classification, risk_score, confidence, payload)
                VALUES (?, ?, ?, ?, ?, ?)""", (
                    result["case_id"], result["created_at"], result["detection"]["classification"],
                    result["risk"]["score"], result["risk"]["confidence"], json.dumps(result),
                ))

    def get(self, case_id: str):
        with self._connect() as connection:
            row = connection.execute("SELECT payload FROM cases WHERE case_id = ?", (case_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def list(self):
        with self._connect() as connection:
            rows = connection.execute("SELECT case_id, created_at, classification, risk_score, confidence FROM cases ORDER BY created_at DESC").fetchall()
        return [dict(zip(("case_id", "created_at", "classification", "risk_score", "confidence"), row)) for row in rows]
