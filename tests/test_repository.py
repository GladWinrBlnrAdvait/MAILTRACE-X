import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.repository import CaseRepository


class TestRepository(unittest.TestCase):
    def test_repository_operations_close_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = CaseRepository(Path(directory) / "cases.db")
            original_connect = repository._connect
            tracked = []
            def connect():
                connection = original_connect()
                tracked.append(connection)
                return connection
            with patch.object(repository, "_connect", side_effect=connect):
                repository.save({
                    "case_id": "CASE-1", "created_at": "2026-01-01T00:00:00Z",
                    "detection": {"classification": "phishing"},
                    "risk": {"score": 80, "confidence": 0.9},
                })
                self.assertIsNotNone(repository.get("CASE-1"))
                self.assertEqual(len(repository.list()), 1)
            for connection in tracked:
                with self.assertRaises(Exception):
                    connection.execute("SELECT 1")


if __name__ == "__main__":
    unittest.main()
