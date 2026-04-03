"""Tests for persistent analyst review note helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.reporting.review_notes import (
    get_analyst_review_for_sha256,
    load_analyst_review_records,
    load_analyst_reviews_by_sha256,
    save_analyst_review,
)


class ReviewNotesTestCase(unittest.TestCase):
    """Validate JSON-backed analyst review note persistence."""

    def test_save_and_load_analyst_review_round_trip(self) -> None:
        """Save one analyst review record and load it back from disk."""
        review_notes_path = PROJECT_ROOT / "tests" / "_review_notes_test_output.json"
        if review_notes_path.exists():
            review_notes_path.unlink()

        try:
            saved_record = save_analyst_review(
                file_name="sample.pdf",
                sha256="abc123",
                source_timestamp="2026-03-29T10:00:00+00:00",
                analyst_note="Opened in restricted environment and queued for escalation.",
                review_status="Under Review",
                priority="High",
                disposition="Suspicious",
                review_notes_path=review_notes_path,
            )
            loaded_records = load_analyst_review_records(review_notes_path=review_notes_path)
        finally:
            if review_notes_path.exists():
                review_notes_path.unlink()

        self.assertEqual(saved_record["sha256"], "abc123")
        self.assertEqual(len(loaded_records), 1)
        self.assertEqual(loaded_records[0]["file_name"], "sample.pdf")
        self.assertEqual(loaded_records[0]["review_status"], "Under Review")
        self.assertEqual(loaded_records[0]["priority"], "High")
        self.assertEqual(loaded_records[0]["disposition"], "Suspicious")

    def test_save_analyst_review_replaces_existing_sha256_record(self) -> None:
        """Update an existing analyst review record when the SHA-256 matches."""
        review_notes_path = PROJECT_ROOT / "tests" / "_review_notes_test_output.json"
        if review_notes_path.exists():
            review_notes_path.unlink()

        try:
            save_analyst_review(
                file_name="sample.pdf",
                sha256="abc123",
                source_timestamp="2026-03-29T10:00:00+00:00",
                analyst_note="Initial review.",
                review_status="New",
                priority="Medium",
                disposition="Suspicious",
                review_notes_path=review_notes_path,
            )
            save_analyst_review(
                file_name="sample.pdf",
                sha256="abc123",
                source_timestamp="2026-03-29T10:00:00+00:00",
                analyst_note="Escalated after exploit chain review.",
                review_status="Escalated",
                priority="Critical",
                disposition="Malicious",
                review_notes_path=review_notes_path,
            )
            loaded_records = load_analyst_review_records(review_notes_path=review_notes_path)
        finally:
            if review_notes_path.exists():
                review_notes_path.unlink()

        self.assertEqual(len(loaded_records), 1)
        self.assertEqual(loaded_records[0]["review_status"], "Escalated")
        self.assertEqual(loaded_records[0]["priority"], "Critical")
        self.assertEqual(loaded_records[0]["disposition"], "Malicious")
        self.assertEqual(
            loaded_records[0]["analyst_note"],
            "Escalated after exploit chain review.",
        )

    def test_load_reviews_by_sha256_and_direct_lookup(self) -> None:
        """Expose saved analyst review records by SHA-256 for UI lookups."""
        review_notes_path = PROJECT_ROOT / "tests" / "_review_notes_test_output.json"
        if review_notes_path.exists():
            review_notes_path.unlink()

        try:
            save_analyst_review(
                file_name="sample.pdf",
                sha256="abc123",
                source_timestamp="2026-03-29T10:00:00+00:00",
                analyst_note="False positive after sandbox replay.",
                review_status="Reviewed",
                priority="Low",
                disposition="False Positive",
                review_notes_path=review_notes_path,
            )
            review_map = load_analyst_reviews_by_sha256(review_notes_path=review_notes_path)
            review_record = get_analyst_review_for_sha256(
                "abc123",
                review_notes_path=review_notes_path,
            )
        finally:
            if review_notes_path.exists():
                review_notes_path.unlink()

        self.assertIn("abc123", review_map)
        self.assertIsNotNone(review_record)
        self.assertEqual(review_map["abc123"]["disposition"], "False Positive")
        self.assertEqual(review_record["review_status"], "Reviewed")
        self.assertEqual(review_record["priority"], "Low")


if __name__ == "__main__":
    unittest.main()
