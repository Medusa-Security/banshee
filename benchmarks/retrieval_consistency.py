"""
Benchmark: retrieval_consistency

Evaluates how consistently a retrieval function returns the same
ranked results across multiple calls. Uses a mock deterministic
retrieval function vs. a noisy one to verify the metrics behave correctly.

In real deployments, replace the retrieval function with your vector DB adapter.
"""

from __future__ import annotations

import random

from banshee.models import MemoryEntry
from banshee.reliability import ReliabilityEvaluator
from benchmarks.base import BenchmarkBase, BenchmarkResult

_QUERIES = [
    "What is retrieval-augmented generation?",
    "How do vector databases store embeddings?",
    "What is prompt injection?",
    "How does memory poisoning work in LLM systems?",
    "What is semantic search?",
]


class RetrievalConsistencyBenchmark(BenchmarkBase):
    """Evaluates retrieval reliability metrics on synthetic retrieval functions.

    Uses two retrieval implementations:
    - Deterministic: always returns the same results → expected RBO ≈ 1.0
    - Noisy: shuffles results randomly → expected RBO < 0.5

    The benchmark passes if the evaluator correctly scores deterministic ≥ 0.95
    and noisy < 0.5 on RBO, demonstrating the metric is sensitive to real drift.
    """

    name = "retrieval_consistency"
    description = "Validates that RBO/NDCG metrics correctly detect retrieval drift."

    def run(self) -> BenchmarkResult:
        base_entries = [MemoryEntry(content=f"Knowledge entry {i}") for i in range(20)]

        def deterministic(query: str) -> list[MemoryEntry]:
            # Same top-5 every time, seeded by query text
            seed = sum(ord(c) for c in query)
            rng = random.Random(seed)
            return rng.sample(base_entries, 5)

        def noisy(query: str) -> list[MemoryEntry]:
            # Completely random order every call
            return random.sample(base_entries, 5)

        evaluator = ReliabilityEvaluator(trials=4, drift_threshold=0.8)

        det_metrics = evaluator.evaluate(_QUERIES, deterministic)
        noisy_metrics = evaluator.evaluate(_QUERIES, noisy)

        det_pass = det_metrics.mean_rbo >= 0.95
        noisy_sensitive = noisy_metrics.mean_rbo < 0.9
        score = (det_metrics.mean_rbo + (1.0 - noisy_metrics.mean_rbo)) / 2.0

        return BenchmarkResult(
            benchmark_name=self.name,
            score=score,
            passed=det_pass and noisy_sensitive,
            metrics={
                "deterministic_rbo": round(det_metrics.mean_rbo, 4),
                "deterministic_ndcg": round(det_metrics.mean_ndcg, 4),
                "deterministic_consistency_rate": round(det_metrics.consistency_rate, 4),
                "noisy_rbo": round(noisy_metrics.mean_rbo, 4),
                "noisy_ndcg": round(noisy_metrics.mean_ndcg, 4),
                "noisy_drifted_queries": len(noisy_metrics.drifted_queries),
                "det_pass": det_pass,
                "noisy_detected_as_inconsistent": noisy_sensitive,
            },
        )
