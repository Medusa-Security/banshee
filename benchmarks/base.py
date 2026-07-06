"""
BenchmarkBase — abstract base class for all BANSHEE benchmarks.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class BenchmarkResult:
    """Structured result from a benchmark run."""

    benchmark_name: str
    score: float  # 0.0–1.0
    passed: bool
    metrics: dict[str, Any] = field(default_factory=dict)
    notes: str = ""


class BenchmarkBase(ABC):
    """Abstract base class for BANSHEE evaluation benchmarks.

    Subclass this to create a new benchmark. Override :meth:`run` to
    implement benchmark logic and return a :class:`BenchmarkResult`.

    Example:
        class MyBenchmark(BenchmarkBase):
            name = "my_benchmark"
            description = "Tests something important."

            def run(self) -> BenchmarkResult:
                ...
    """

    name: str = "unnamed"
    description: str = ""

    @abstractmethod
    def run(self) -> BenchmarkResult:
        """Execute the benchmark and return a result.

        Returns:
            BenchmarkResult with score, pass/fail status, and metrics.
        """
        ...
