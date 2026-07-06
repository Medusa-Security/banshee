"""
IntegrityVerifier — evaluates memory entries for integrity violations.
"""

from __future__ import annotations

import logging
import math
from typing import Sequence

from banshee.integrity.checksums import verify_checksum
from banshee.models import IntegrityReport, IntegrityStatus, MemoryEntry, RiskLevel

logger = logging.getLogger(__name__)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two equal-length vectors.

    Args:
        a: First embedding vector.
        b: Second embedding vector.

    Returns:
        Cosine similarity in [-1, 1]. Returns 0.0 if either vector is zero.
    """
    if len(a) != len(b):
        raise ValueError(f"Embedding dimension mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b))
    mag_a = math.sqrt(sum(x * x for x in a))
    mag_b = math.sqrt(sum(y * y for y in b))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


class IntegrityVerifier:
    """Verifies the integrity of memory entries in an AI memory store.

    Checks performed:
    - **Checksum validation**: detects content modification since ingestion.
    - **Embedding drift**: flags entries where the stored embedding is
      geometrically inconsistent with a freshly computed reference embedding,
      which can indicate embedding inversion attacks or silent re-indexing.
    - **Timestamp sanity**: detects impossible or suspicious timestamp orderings.
    - **Content quality**: catches empty or whitespace-only entries.

    The ``embedding_verifier`` is a callable that takes a content string and
    returns a freshly computed embedding. If not provided, embedding drift
    checks are skipped.

    Example:
        >>> verifier = IntegrityVerifier()
        >>> report = verifier.check_entry(entry)
        >>> print(report.status)

        # With embedding drift detection:
        >>> from openai import OpenAI
        >>> client = OpenAI()
        >>> def embed(text): return client.embeddings.create(...).data[0].embedding
        >>> verifier = IntegrityVerifier(embedding_verifier=embed)
    """

    def __init__(
        self,
        embedding_drift_threshold: float = 0.05,
        embedding_verifier: "EmbeddingFn | None" = None,
    ) -> None:
        """
        Args:
            embedding_drift_threshold: Cosine *distance* (1 - similarity) above
                which an embedding is flagged as drifted. 0.05 means ~5% angular
                deviation. Tighten to 0.01 for high-security environments.
            embedding_verifier: Optional callable ``(content: str) -> list[float]``
                that produces a fresh embedding for a content string. When
                provided, stored embeddings are compared against fresh ones.
        """
        self.embedding_drift_threshold = embedding_drift_threshold
        self.embedding_verifier = embedding_verifier

    def check_entry(self, entry: MemoryEntry) -> IntegrityReport:
        """Run all integrity checks against a single memory entry.

        Args:
            entry: The memory entry to verify.

        Returns:
            An IntegrityReport with status, risk level, and any detected issues.
        """
        issues: list[str] = []
        risk = RiskLevel.NONE
        details: dict = {}

        # ---- 1. Checksum verification ----------------------------------------
        if entry.checksum is None:
            issues.append("No checksum stored — entry cannot be cryptographically verified.")
            status = IntegrityStatus.UNVERIFIED
            risk = RiskLevel.LOW
        elif not verify_checksum(entry.content, entry.checksum):
            issues.append(
                "Checksum mismatch — content has changed since ingestion. "
                "This is the primary indicator of tampering or corruption."
            )
            status = IntegrityStatus.TAMPERED
            risk = RiskLevel.CRITICAL
        else:
            status = IntegrityStatus.VERIFIED

        # ---- 2. Embedding drift detection ------------------------------------
        if (
            entry.embedding is not None
            and self.embedding_verifier is not None
            and status != IntegrityStatus.TAMPERED  # tamper already confirmed above
        ):
            try:
                fresh_embedding = self.embedding_verifier(entry.content)
                similarity = _cosine_similarity(entry.embedding, fresh_embedding)
                distance = 1.0 - similarity
                details["embedding_cosine_distance"] = round(distance, 6)
                details["embedding_cosine_similarity"] = round(similarity, 6)

                if distance > self.embedding_drift_threshold:
                    issues.append(
                        f"Embedding drift detected: cosine distance {distance:.4f} exceeds "
                        f"threshold {self.embedding_drift_threshold}. "
                        "The stored embedding may have been tampered with or re-indexed "
                        "without updating the content checksum."
                    )
                    risk = max(risk, RiskLevel.HIGH) if risk >= RiskLevel.HIGH else RiskLevel.HIGH
                    if status == IntegrityStatus.VERIFIED:
                        # Content is intact but embedding is wrong — suspicious
                        status = IntegrityStatus.CORRUPTED
            except Exception as exc:
                logger.warning("Embedding drift check failed for entry %s: %s", entry.id, exc)
                issues.append(f"Embedding drift check could not complete: {exc}")

        # ---- 3. Timestamp sanity --------------------------------------------
        if entry.updated_at < entry.created_at:
            issues.append(
                f"updated_at ({entry.updated_at.isoformat()}) predates created_at "
                f"({entry.created_at.isoformat()}) — possible clock skew or timestamp forgery."
            )
            risk = max(risk, RiskLevel.HIGH) if risk >= RiskLevel.HIGH else RiskLevel.HIGH

        # ---- 4. Content quality ---------------------------------------------
        if not entry.content.strip():
            issues.append("Memory entry content is empty or whitespace only.")
            risk = max(risk, RiskLevel.MEDIUM) if risk >= RiskLevel.MEDIUM else RiskLevel.MEDIUM

        logger.debug(
            "Checked entry %s: status=%s risk=%s issues=%d",
            entry.id, status, risk, len(issues),
        )

        return IntegrityReport(
            entry_id=entry.id,
            status=status,
            risk_level=risk,
            issues=issues,
            details=details,
        )

    def check_store(self, entries: Sequence[MemoryEntry]) -> list[IntegrityReport]:
        """Run integrity checks on an entire memory store.

        Args:
            entries: Sequence of memory entries to verify.

        Returns:
            List of IntegrityReports, one per entry, in the same order.
        """
        return [self.check_entry(entry) for entry in entries]

    def summarize(self, reports: list[IntegrityReport]) -> dict[str, int]:
        """Produce a status count summary across a batch of reports.

        Args:
            reports: List of IntegrityReport objects.

        Returns:
            Dict mapping status names to counts.
        """
        summary: dict[str, int] = {s.value: 0 for s in IntegrityStatus}
        for report in reports:
            summary[report.status.value] += 1
        return summary


# Type alias for the embedding verifier callable
from typing import Callable
EmbeddingFn = Callable[[str], list[float]]
