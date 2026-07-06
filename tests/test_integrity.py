"""
Tests for banshee.integrity module.
"""

import math
import pytest
from banshee.integrity import IntegrityVerifier, compute_checksum, verify_checksum
from banshee.models import IntegrityStatus, MemoryEntry


# ---------------------------------------------------------------------------
# Checksum utilities
# ---------------------------------------------------------------------------

class TestComputeChecksum:
    def test_sha256_format(self):
        result = compute_checksum("hello world")
        assert result.startswith("sha256:")

    def test_sha512_format(self):
        result = compute_checksum("hello world", algorithm="sha512")
        assert result.startswith("sha512:")

    def test_blake2b_format(self):
        result = compute_checksum("hello world", algorithm="blake2b")
        assert result.startswith("blake2b:")

    def test_deterministic(self):
        assert compute_checksum("test") == compute_checksum("test")

    def test_different_content_different_hash(self):
        assert compute_checksum("abc") != compute_checksum("xyz")

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_checksum("content", algorithm="md5")  # type: ignore


class TestVerifyChecksum:
    def test_valid_checksum_returns_true(self):
        content = "hello world"
        checksum = compute_checksum(content)
        assert verify_checksum(content, checksum) is True

    def test_modified_content_returns_false(self):
        checksum = compute_checksum("original")
        assert verify_checksum("modified", checksum) is False

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="Invalid checksum format"):
            verify_checksum("content", "nocolon")


# ---------------------------------------------------------------------------
# IntegrityVerifier
# ---------------------------------------------------------------------------

class TestIntegrityVerifier:
    def _make_entry(self, content: str, with_checksum: bool = True) -> MemoryEntry:
        checksum = compute_checksum(content) if with_checksum else None
        return MemoryEntry(content=content, checksum=checksum)

    def test_verified_entry(self):
        entry = self._make_entry("clean content")
        verifier = IntegrityVerifier()
        report = verifier.check_entry(entry)
        assert report.status == IntegrityStatus.VERIFIED
        assert len(report.issues) == 0

    def test_tampered_entry(self):
        entry = MemoryEntry(
            content="modified content",
            checksum=compute_checksum("original content"),
        )
        verifier = IntegrityVerifier()
        report = verifier.check_entry(entry)
        assert report.status == IntegrityStatus.TAMPERED

    def test_missing_checksum_is_unverified(self):
        entry = self._make_entry("content", with_checksum=False)
        verifier = IntegrityVerifier()
        report = verifier.check_entry(entry)
        assert report.status == IntegrityStatus.UNVERIFIED
        assert any("No checksum" in issue for issue in report.issues)

    def test_check_store_returns_one_report_per_entry(self):
        entries = [self._make_entry(f"entry {i}") for i in range(5)]
        verifier = IntegrityVerifier()
        reports = verifier.check_store(entries)
        assert len(reports) == 5

    def test_summarize(self):
        entries = [
            self._make_entry("clean"),
            MemoryEntry(content="tampered", checksum=compute_checksum("original")),
        ]
        verifier = IntegrityVerifier()
        reports = verifier.check_store(entries)
        summary = verifier.summarize(reports)
        assert summary["verified"] == 1
        assert summary["tampered"] == 1

    def test_embedding_drift_detected(self):
        """Verifier should flag CORRUPTED when embedding diverges from fresh embedding."""
        content = "test content"
        original_embedding = [1.0, 0.0, 0.0]
        # A drifted embedding is orthogonal to the original
        drifted_embedding = [0.0, 1.0, 0.0]

        entry = MemoryEntry(
            content=content,
            checksum=compute_checksum(content),
            embedding=drifted_embedding,
        )

        def mock_embedder(text: str) -> list[float]:
            return original_embedding  # fresh embedding is very different

        verifier = IntegrityVerifier(
            embedding_drift_threshold=0.05,
            embedding_verifier=mock_embedder,
        )
        report = verifier.check_entry(entry)
        assert report.status == IntegrityStatus.CORRUPTED
        assert "embedding_cosine_distance" in report.details
        assert report.details["embedding_cosine_distance"] > 0.05

    def test_no_drift_when_embeddings_match(self):
        """Verifier should not flag embedding drift when similarity is high."""
        content = "test content"
        embedding = [1.0, 0.0, 0.0]

        entry = MemoryEntry(
            content=content,
            checksum=compute_checksum(content),
            embedding=embedding,
        )

        def mock_embedder(text: str) -> list[float]:
            return [0.9999, 0.001, 0.0]  # nearly identical

        verifier = IntegrityVerifier(
            embedding_drift_threshold=0.05,
            embedding_verifier=mock_embedder,
        )
        report = verifier.check_entry(entry)
        assert report.status == IntegrityStatus.VERIFIED
