"""
Benchmark: integrity_basic

Tests whether IntegrityVerifier correctly identifies tampered entries.
"""

from __future__ import annotations

from banshee.integrity import IntegrityVerifier, compute_checksum
from banshee.models import IntegrityStatus, MemoryEntry
from benchmarks.base import BenchmarkBase, BenchmarkResult


class IntegrityBasicBenchmark(BenchmarkBase):
    """Evaluates checksum-based tamper detection on a synthetic dataset.

    Creates a mix of clean and tampered entries and measures detection accuracy.
    """

    name = "integrity_basic"
    description = "Detects checksum mismatches on modified memory entries."

    def run(self) -> BenchmarkResult:
        verifier = IntegrityVerifier()

        # Build clean entries
        clean_entries = [
            MemoryEntry(content=f"Clean memory entry {i}", checksum=compute_checksum(f"Clean memory entry {i}"))
            for i in range(10)
        ]

        # Build tampered entries: checksum stored from original, but content changed
        tampered_entries = [
            MemoryEntry(
                content=f"Tampered content {i}",
                checksum=compute_checksum(f"Original content {i}"),  # stale checksum
            )
            for i in range(5)
        ]

        all_entries = clean_entries + tampered_entries
        reports = verifier.check_store(all_entries)

        detected_tampered = sum(
            1 for r in reports[len(clean_entries):]
            if r.status == IntegrityStatus.TAMPERED
        )
        false_positives = sum(
            1 for r in reports[:len(clean_entries)]
            if r.status == IntegrityStatus.TAMPERED
        )

        recall = detected_tampered / len(tampered_entries)
        precision = detected_tampered / (detected_tampered + false_positives) if (detected_tampered + false_positives) > 0 else 1.0
        score = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return BenchmarkResult(
            benchmark_name=self.name,
            score=score,
            passed=score >= 0.95,
            metrics={
                "total_entries": len(all_entries),
                "tampered_detected": detected_tampered,
                "false_positives": false_positives,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(score, 4),
            },
        )
