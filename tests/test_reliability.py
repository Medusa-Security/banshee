"""
Tests for banshee.reliability module — covers all metric implementations.
"""

import pytest
from banshee.models import MemoryEntry
from banshee.reliability import ReliabilityEvaluator
from banshee.reliability.evaluator import jaccard, ndcg, rbo, reciprocal_rank


# ---------------------------------------------------------------------------
# Unit tests for individual metric functions
# ---------------------------------------------------------------------------

class TestJaccard:
    def test_identical_sets(self):
        assert jaccard({"a", "b", "c"}, {"a", "b", "c"}) == 1.0

    def test_disjoint_sets(self):
        assert jaccard({"a", "b"}, {"c", "d"}) == 0.0

    def test_partial_overlap(self):
        score = jaccard({"a", "b", "c"}, {"b", "c", "d"})
        assert 0.0 < score < 1.0

    def test_empty_sets(self):
        assert jaccard(set(), set()) == 1.0


class TestRBO:
    def test_identical_lists(self):
        lst = ["a", "b", "c", "d"]
        assert rbo(lst, lst) == pytest.approx(1.0, abs=1e-6)

    def test_empty_lists(self):
        assert rbo([], []) == 1.0

    def test_completely_different(self):
        assert rbo(["a", "b"], ["c", "d"]) == pytest.approx(0.0, abs=1e-6)

    def test_top_heavy_weighting(self):
        # Same top-1, different rest → should score higher than same bottom, different top
        same_top = rbo(["a", "b", "c"], ["a", "d", "e"])
        same_bottom = rbo(["b", "c", "a"], ["d", "e", "a"])
        assert same_top > same_bottom

    def test_reversed_list_scores_lower_than_identical(self):
        lst = ["a", "b", "c", "d"]
        rev = list(reversed(lst))
        assert rbo(lst, lst) > rbo(lst, rev)


class TestReciprocalRank:
    def test_top_match(self):
        assert reciprocal_rank(["a", "b"], ["a", "c"]) == 1.0

    def test_second_position(self):
        assert reciprocal_rank(["a", "b"], ["b", "a"]) == pytest.approx(0.5)

    def test_not_found(self):
        assert reciprocal_rank(["a"], ["b", "c"]) == 0.0

    def test_empty_inputs(self):
        assert reciprocal_rank([], ["a"]) == 0.0
        assert reciprocal_rank(["a"], []) == 0.0


class TestNDCG:
    def test_identical_lists(self):
        lst = ["a", "b", "c"]
        assert ndcg(lst, lst) == pytest.approx(1.0, abs=1e-6)

    def test_disjoint_lists(self):
        assert ndcg(["a", "b"], ["c", "d"]) == pytest.approx(0.0, abs=1e-6)

    def test_partial_overlap_less_than_1(self):
        score = ndcg(["a", "b", "c"], ["a", "c", "b"])
        assert 0.0 < score <= 1.0


# ---------------------------------------------------------------------------
# ReliabilityEvaluator integration tests
# ---------------------------------------------------------------------------

class TestReliabilityEvaluator:
    def _make_entries(self, n: int) -> list[MemoryEntry]:
        return [MemoryEntry(content=f"entry {i}") for i in range(n)]

    def test_consistent_retrieval_perfect_scores(self):
        entries = self._make_entries(5)

        def always_same(query: str) -> list[MemoryEntry]:
            return entries[:3]

        evaluator = ReliabilityEvaluator(trials=3)
        metrics = evaluator.evaluate(["q1", "q2"], always_same)
        assert metrics.consistency_rate == 1.0
        assert metrics.mean_jaccard == pytest.approx(1.0)
        assert metrics.mean_rbo == pytest.approx(1.0)

    def test_inconsistent_retrieval_lowers_scores(self):
        import itertools
        entries = self._make_entries(6)
        cycle = itertools.cycle([entries[:3], entries[3:]])

        def alternating(query: str) -> list[MemoryEntry]:
            return next(cycle)

        evaluator = ReliabilityEvaluator(trials=2)
        metrics = evaluator.evaluate(["q1"], alternating)
        assert metrics.consistency_rate == 0.0
        assert metrics.mean_jaccard < 1.0
        assert metrics.mean_rbo < 1.0

    def test_drift_detected_on_noisy_retrieval(self):
        import random
        entries = self._make_entries(20)

        def noisy(query: str) -> list[MemoryEntry]:
            return random.sample(entries, 5)

        evaluator = ReliabilityEvaluator(trials=3, drift_threshold=0.99)
        metrics = evaluator.evaluate(["q1", "q2", "q3"], noisy)
        assert len(metrics.drifted_queries) > 0

    def test_summary_has_expected_keys(self):
        entries = self._make_entries(3)
        evaluator = ReliabilityEvaluator(trials=2)
        metrics = evaluator.evaluate(["q"], lambda q: entries[:2])
        summary = metrics.summary()
        for key in ["total_queries", "consistency_rate", "mean_jaccard", "mean_rbo", "mean_mrr", "mean_ndcg"]:
            assert key in summary

    def test_trials_less_than_2_raises(self):
        with pytest.raises(ValueError, match="trials must be >= 2"):
            ReliabilityEvaluator(trials=1)

    def test_empty_queries_returns_zero_consistency(self):
        evaluator = ReliabilityEvaluator()
        metrics = evaluator.evaluate([], lambda q: [])
        assert metrics.total_queries == 0
        assert metrics.consistency_rate == 0.0

    def test_query_results_count_matches_queries(self):
        entries = self._make_entries(3)
        evaluator = ReliabilityEvaluator(trials=2)
        metrics = evaluator.evaluate(["q1", "q2", "q3"], lambda q: entries)
        assert len(metrics.query_results) == 3
