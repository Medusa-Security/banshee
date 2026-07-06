"""
ReliabilityEvaluator — measures retrieval consistency of AI memory systems.

Metrics implemented:
- Jaccard consistency     : set-level overlap across repeated queries (binary)
- RBO (Rank-Biased Overlap): rank-aware overlap; penalizes position changes
- MRR (Mean Reciprocal Rank): measures consistency of the top-1 result
- NDCG@k consistency     : normalized discounted cumulative gain drift
- Drift detection         : flags queries where results change significantly
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import Callable, Sequence

from banshee.models import MemoryEntry

logger = logging.getLogger(__name__)

RetrievalFn = Callable[[str], list[MemoryEntry]]


# ---------------------------------------------------------------------------
# Ranking metrics (pure functions, no external deps)
# ---------------------------------------------------------------------------


def jaccard(set_a: set[str], set_b: set[str]) -> float:
    """Jaccard similarity between two sets."""
    union = set_a | set_b
    return len(set_a & set_b) / len(union) if union else 1.0


def rbo(list_a: list[str], list_b: list[str], p: float = 0.95) -> float:
    """Rank-Biased Overlap (Webber et al. 2010).

    A rank-aware similarity metric in [0, 1]. Results at higher ranks
    (position 1, 2 …) are weighted more than lower ranks. ``p`` controls
    the persistence parameter — higher p gives more weight to deeper ranks.

    Uses the convergent RBO_EXT formula which correctly returns 1.0 for
    identical lists.

    Args:
        list_a: Ranked list of result IDs (first = rank 1).
        list_b: Ranked list of result IDs.
        p: Persistence parameter in (0, 1). Default 0.95 is standard.

    Returns:
        RBO score in [0, 1]. 1.0 means identical ranked lists.
    """
    if not list_a and not list_b:
        return 1.0
    if not list_a or not list_b:
        return 0.0

    k = max(len(list_a), len(list_b))
    x_k = len(set(list_a) & set(list_b))

    # Build the overlap at each depth
    overlaps: list[float] = []
    for d in range(1, k + 1):
        set_a = set(list_a[:d])
        set_b = set(list_b[:d])
        overlaps.append(len(set_a & set_b) / d)

    # RBO_EXT closed form
    sum_term = sum((p ** (d - 1)) * overlaps[d - 1] for d in range(1, k + 1))
    rbo_ext = (1 - p) * sum_term + (p ** k) * (x_k / k)

    return min(rbo_ext, 1.0)


def reciprocal_rank(list_a: list[str], list_b: list[str]) -> float:
    """Consistency of the rank-1 result between two ranked lists.

    Returns 1/rank of the first trial's top result in the second trial.
    Returns 0.0 if the top result from trial A does not appear in trial B.

    Args:
        list_a: First trial's ranked result IDs.
        list_b: Second trial's ranked result IDs.
    """
    if not list_a or not list_b:
        return 0.0
    top_item = list_a[0]
    try:
        rank = list_b.index(top_item) + 1  # 1-indexed
        return 1.0 / rank
    except ValueError:
        return 0.0


def ndcg(list_a: list[str], list_b: list[str], k: int = 10) -> float:
    """NDCG@k consistency between two ranked lists.

    Uses list_a as the "ideal" ranking (relevance = 1/log2(rank+1))
    and scores list_b against it.

    Args:
        list_a: Reference (ideal) ranked list.
        list_b: Candidate ranked list.
        k: Cutoff depth.
    """
    def dcg(ranked: list[str], ideal_order: list[str], cutoff: int) -> float:
        score = 0.0
        for i, item in enumerate(ranked[:cutoff], start=1):
            if item in ideal_order:
                ideal_rank = ideal_order.index(item) + 1
                relevance = 1.0 / math.log2(ideal_rank + 1)
                score += relevance / math.log2(i + 1)
        return score

    ideal_dcg = dcg(list_a[:k], list_a, k)
    if ideal_dcg == 0:
        return 1.0  # both empty
    return min(dcg(list_b[:k], list_a, k) / ideal_dcg, 1.0)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class QueryResult:
    """Per-query reliability measurements across all metric families."""

    query: str
    jaccard_mean: float = 0.0
    rbo_mean: float = 0.0
    mrr_mean: float = 0.0
    ndcg_mean: float = 0.0
    is_consistent: bool = True  # True iff Jaccard >= 1.0 (exact set match)
    drift_detected: bool = False
    trials: list[list[str]] = field(default_factory=list)


@dataclass
class ReliabilityMetrics:
    """Aggregated reliability metrics for a retrieval system evaluation."""

    total_queries: int = 0
    trials_per_query: int = 2
    consistent_retrievals: int = 0
    inconsistent_retrievals: int = 0

    # Mean scores across all queries
    mean_jaccard: float = 0.0
    mean_rbo: float = 0.0
    mean_mrr: float = 0.0
    mean_ndcg: float = 0.0

    # Queries where significant drift was detected
    drifted_queries: list[str] = field(default_factory=list)
    query_results: list[QueryResult] = field(default_factory=list)

    @property
    def consistency_rate(self) -> float:
        """Fraction of queries with identical result sets across all trials."""
        return self.consistent_retrievals / self.total_queries if self.total_queries else 0.0

    def summary(self) -> dict[str, float | int]:
        return {
            "total_queries": self.total_queries,
            "consistency_rate": round(self.consistency_rate, 4),
            "mean_jaccard": round(self.mean_jaccard, 4),
            "mean_rbo": round(self.mean_rbo, 4),
            "mean_mrr": round(self.mean_mrr, 4),
            "mean_ndcg": round(self.mean_ndcg, 4),
            "drifted_queries": len(self.drifted_queries),
        }


# ---------------------------------------------------------------------------
# Evaluator
# ---------------------------------------------------------------------------


class ReliabilityEvaluator:
    """Evaluates retrieval consistency of an AI memory system.

    Issues repeated queries and measures how consistently the same results
    are returned across multiple metrics. Low scores may indicate:
    - Embedding model instability or re-indexing
    - Non-deterministic approximate nearest-neighbour search
    - Index corruption or partial write failures
    - Load-dependent retrieval inconsistencies

    Metrics reported:
    - **Jaccard**: exact set overlap (order-insensitive)
    - **RBO**: rank-biased overlap (order-sensitive, top-heavy weighting)
    - **MRR**: mean reciprocal rank of the top-1 result's position across trials
    - **NDCG@k**: normalized discounted cumulative gain consistency

    Example:
        >>> evaluator = ReliabilityEvaluator(trials=5, rbo_p=0.95)
        >>> metrics = evaluator.evaluate(queries, retrieval_fn)
        >>> print(metrics.summary())
    """

    def __init__(
        self,
        trials: int = 3,
        rbo_p: float = 0.95,
        ndcg_k: int = 10,
        drift_threshold: float = 0.8,
    ) -> None:
        """
        Args:
            trials: Number of times to issue each query. Minimum 2.
            rbo_p: RBO persistence parameter. Higher values weight deeper ranks.
            ndcg_k: NDCG cutoff depth.
            drift_threshold: RBO score below this triggers ``drift_detected=True``
                on the QueryResult. Helps surface the worst offenders.
        """
        if trials < 2:
            raise ValueError("trials must be >= 2 to measure consistency.")
        self.trials = trials
        self.rbo_p = rbo_p
        self.ndcg_k = ndcg_k
        self.drift_threshold = drift_threshold

    def evaluate(
        self,
        queries: Sequence[str],
        retrieval_fn: RetrievalFn,
    ) -> ReliabilityMetrics:
        """Evaluate retrieval consistency across a set of queries.

        Args:
            queries: Query strings to test.
            retrieval_fn: Callable ``(query: str) -> list[MemoryEntry]``.

        Returns:
            ReliabilityMetrics with per-query and aggregate scores.
        """
        metrics = ReliabilityMetrics(total_queries=len(queries), trials_per_query=self.trials)

        jaccards, rbos, mrrs, ndcgs = [], [], [], []

        for query in queries:
            result_lists: list[list[str]] = []
            for _ in range(self.trials):
                result_lists.append([str(e.id) for e in retrieval_fn(query)])

            qr = self._score_query(query, result_lists)
            metrics.query_results.append(qr)

            jaccards.append(qr.jaccard_mean)
            rbos.append(qr.rbo_mean)
            mrrs.append(qr.mrr_mean)
            ndcgs.append(qr.ndcg_mean)

            if qr.is_consistent:
                metrics.consistent_retrievals += 1
            else:
                metrics.inconsistent_retrievals += 1

            if qr.drift_detected:
                metrics.drifted_queries.append(query)

        def _mean(lst: list[float]) -> float:
            return sum(lst) / len(lst) if lst else 0.0

        metrics.mean_jaccard = _mean(jaccards)
        metrics.mean_rbo = _mean(rbos)
        metrics.mean_mrr = _mean(mrrs)
        metrics.mean_ndcg = _mean(ndcgs)

        logger.info(
            "Reliability eval: %d queries, consistency=%.1f%%, RBO=%.3f, NDCG=%.3f",
            len(queries),
            metrics.consistency_rate * 100,
            metrics.mean_rbo,
            metrics.mean_ndcg,
        )
        return metrics

    def _score_query(self, query: str, result_lists: list[list[str]]) -> QueryResult:
        """Compute all consistency metrics for one query across its trials."""
        n = len(result_lists)
        jac_scores, rbo_scores, mrr_scores, ndcg_scores = [], [], [], []

        for i in range(n):
            for j in range(i + 1, n):
                a, b = result_lists[i], result_lists[j]
                jac_scores.append(jaccard(set(a), set(b)))
                rbo_scores.append(rbo(a, b, p=self.rbo_p))
                mrr_scores.append(reciprocal_rank(a, b))
                ndcg_scores.append(ndcg(a, b, k=self.ndcg_k))

        def _mean(lst: list[float]) -> float:
            return sum(lst) / len(lst) if lst else 1.0

        j_mean = _mean(jac_scores)
        r_mean = _mean(rbo_scores)

        return QueryResult(
            query=query,
            jaccard_mean=j_mean,
            rbo_mean=r_mean,
            mrr_mean=_mean(mrr_scores),
            ndcg_mean=_mean(ndcg_scores),
            is_consistent=j_mean >= 1.0,
            drift_detected=r_mean < self.drift_threshold,
            trials=result_lists,
        )
