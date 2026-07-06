"""
Benchmark: poisoning_detection

Evaluates PoisoningDetector precision and recall against a labeled dataset
of clean and adversarial memory entries.

Ground truth labels come from datasets/poisoning/injection_examples.json
and datasets/synthetic/clean_entries.json.
"""

from __future__ import annotations

import json
from pathlib import Path

from banshee.models import MemoryEntry
from banshee.security import PoisoningDetector
from benchmarks.base import BenchmarkBase, BenchmarkResult

_DATASETS_DIR = Path(__file__).parent.parent / "datasets"


class PoisoningDetectionBenchmark(BenchmarkBase):
    """Evaluates the PoisoningDetector against labeled injection and clean entries.

    Measures:
    - True positive rate (recall): fraction of malicious entries caught
    - False positive rate: fraction of clean entries incorrectly flagged
    - Precision and F1
    """

    name = "poisoning_detection"
    description = "Precision/recall of PoisoningDetector on labeled dataset."

    def run(self) -> BenchmarkResult:
        detector = PoisoningDetector()

        malicious_entries = self._load(
            _DATASETS_DIR / "poisoning" / "injection_examples.json", expected_label="malicious"
        )
        clean_entries = self._load(
            _DATASETS_DIR / "synthetic" / "clean_entries.json", expected_label="clean"
        )

        # Scan malicious — count true positives
        tp = 0
        for entry in malicious_entries:
            if detector.scan_entry(entry):
                tp += 1

        # Scan clean — count false positives
        fp = 0
        for entry in clean_entries:
            if detector.scan_entry(entry):
                fp += 1

        fn = len(malicious_entries) - tp
        tn = len(clean_entries) - fp

        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / len(clean_entries) if clean_entries else 0.0

        return BenchmarkResult(
            benchmark_name=self.name,
            score=f1,
            passed=recall >= 0.80 and fpr <= 0.20,
            metrics={
                "malicious_entries": len(malicious_entries),
                "clean_entries": len(clean_entries),
                "true_positives": tp,
                "false_positives": fp,
                "false_negatives": fn,
                "true_negatives": tn,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1, 4),
                "false_positive_rate": round(fpr, 4),
            },
        )

    @staticmethod
    def _load(path: Path, expected_label: str) -> list[MemoryEntry]:
        if not path.exists():
            return []
        raw = json.loads(path.read_text(encoding="utf-8"))
        return [MemoryEntry(**item) for item in raw]
