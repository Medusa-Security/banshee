"""
BANSHEE Benchmark Runner.

Usage:
    python -m benchmarks.run
    python -m benchmarks.run --benchmark integrity_basic
    python -m benchmarks.run --benchmark poisoning_detection
    python -m benchmarks.run --list
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from benchmarks.base import BenchmarkBase, BenchmarkResult
from benchmarks.integrity_basic import IntegrityBasicBenchmark
from benchmarks.poisoning_detection import PoisoningDetectionBenchmark
from benchmarks.retrieval_consistency import RetrievalConsistencyBenchmark

REGISTRY: dict[str, type[BenchmarkBase]] = {
    "integrity_basic": IntegrityBasicBenchmark,
    "poisoning_detection": PoisoningDetectionBenchmark,
    "retrieval_consistency": RetrievalConsistencyBenchmark,
}

PASS_MARK = "\033[92m✓ PASS\033[0m"
FAIL_MARK = "\033[91m✗ FAIL\033[0m"


def run_benchmark(name: str) -> BenchmarkResult:
    cls = REGISTRY[name]
    print(f"\n▶ Running: {name}")
    print(f"  {cls.description}")
    start = time.perf_counter()
    result = cls().run()
    elapsed = time.perf_counter() - start
    status = PASS_MARK if result.passed else FAIL_MARK
    print(f"  {status}  score={result.score:.4f}  ({elapsed:.3f}s)")
    for k, v in result.metrics.items():
        print(f"    {k:30s}: {v}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="BANSHEE Benchmark Runner")
    parser.add_argument("--benchmark", "-b", help="Name of benchmark to run (default: all)")
    parser.add_argument("--list", "-l", action="store_true", help="List available benchmarks")
    parser.add_argument("--json", "-j", metavar="FILE", help="Write results to a JSON file")
    args = parser.parse_args()

    if args.list:
        print("Available benchmarks:")
        for name, cls in REGISTRY.items():
            print(f"  {name:30s} — {cls.description}")
        return

    names = [args.benchmark] if args.benchmark else list(REGISTRY.keys())
    for n in names:
        if n not in REGISTRY:
            print(f"Unknown benchmark: {n!r}. Use --list to see available benchmarks.")
            sys.exit(1)

    results: list[BenchmarkResult] = []
    for name in names:
        results.append(run_benchmark(name))

    passed = sum(1 for r in results if r.passed)
    total = len(results)
    print(f"\nResults: {passed}/{total} passed")

    if args.json:
        data = [
            {"benchmark": r.benchmark_name, "score": r.score, "passed": r.passed, "metrics": r.metrics}
            for r in results
        ]
        with open(args.json, "w") as f:
            json.dump(data, f, indent=2, default=str)
        print(f"Results written to {args.json}")

    if passed < total:
        sys.exit(1)


if __name__ == "__main__":
    main()
