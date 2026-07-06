"""
ProvenanceTracker — records, queries, and updates memory entry lineage.

Key capabilities beyond basic logging:
- Trust propagation: trust from a parent source is inherited by derived entries
- Trust decay: configurable decay factor when trust propagates through hops
- Trust update history: every change is append-only for auditability
- Graph-aware lineage: parent→child relationships between entries
"""

from __future__ import annotations

import logging
from datetime import timezone
from typing import Any
from uuid import UUID

from banshee.models import AuditEvent, AuditEventType, MemoryEntry, ProvenanceRecord, _utcnow

logger = logging.getLogger(__name__)


class ProvenanceTracker:
    """Tracks provenance records for AI memory entries.

    Maintains an in-memory registry of ProvenanceRecords with support for:
    - Trust score assignment and update with full history
    - Trust propagation through parent→child derivation chains
    - Transformation logging (chunk, embed, summarize, translate, etc.)
    - Audit event emission for integration with external audit systems

    In production, back this with an append-only store (event sourcing,
    write-ahead log, or an immutable database like Amazon QLDB).

    Example:
        >>> tracker = ProvenanceTracker(trust_decay=0.9)
        >>> tracker.register(entry, source_uri="https://example.com", trust_score=0.95)
        >>> tracker.record_transformation(entry.id, "chunk", {"size": 512})
        >>> lineage = tracker.get(entry.id)
        >>> print(lineage.trust_score)
    """

    def __init__(self, trust_decay: float = 0.9) -> None:
        """
        Args:
            trust_decay: Multiplier applied when propagating trust through
                derivation hops. 0.9 means a child entry gets 90% of its
                parent's trust score. Range: (0, 1].
        """
        if not (0 < trust_decay <= 1.0):
            raise ValueError("trust_decay must be in the range (0, 1].")
        self.trust_decay = trust_decay
        self._records: dict[UUID, ProvenanceRecord] = {}
        self._parent_map: dict[UUID, UUID] = {}   # child_id → parent_id
        self._audit_log: list[AuditEvent] = []

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(
        self,
        entry: MemoryEntry,
        source_uri: str | None = None,
        author: str | None = None,
        trust_score: float = 1.0,
        parent_id: UUID | None = None,
        actor: str = "system",
    ) -> ProvenanceRecord:
        """Register a new provenance record for a memory entry.

        If ``parent_id`` is provided and the parent has a provenance record,
        the trust score is set to ``min(trust_score, parent.trust_score * trust_decay)``
        to prevent privilege escalation through derivation.

        Args:
            entry: The memory entry being registered.
            source_uri: Origin URI (overrides ``entry.source`` if given).
            author: Identifier for the author or ingestion pipeline.
            trust_score: Requested trust score. May be reduced by parent trust.
            parent_id: UUID of a parent entry this entry was derived from.
            actor: Component performing the registration (for audit log).

        Returns:
            The created ProvenanceRecord.
        """
        # Trust propagation: cap trust at parent's decayed trust
        effective_trust = trust_score
        if parent_id is not None and parent_id in self._records:
            parent_trust = self._records[parent_id].trust_score
            propagated = parent_trust * self.trust_decay
            if trust_score > propagated:
                logger.debug(
                    "Trust capped from %.3f → %.3f via parent %s propagation",
                    trust_score, propagated, parent_id,
                )
                effective_trust = propagated
            self._parent_map[entry.id] = parent_id

        record = ProvenanceRecord(
            entry_id=entry.id,
            source_uri=source_uri or entry.source,
            author=author,
            trust_score=round(effective_trust, 4),
            trust_history=[
                {
                    "trust_score": round(effective_trust, 4),
                    "timestamp": _utcnow().isoformat(),
                    "reason": "initial_registration",
                    "actor": actor,
                    "parent_id": str(parent_id) if parent_id else None,
                }
            ],
        )
        self._records[entry.id] = record

        self._emit(AuditEvent(
            event_type=AuditEventType.INGESTED,
            entry_id=entry.id,
            actor=actor,
            payload={"source_uri": record.source_uri, "trust_score": record.trust_score},
        ))

        logger.debug("Registered entry %s (source=%s trust=%.3f)", entry.id, record.source_uri, record.trust_score)
        return record

    # ------------------------------------------------------------------
    # Trust management
    # ------------------------------------------------------------------

    def update_trust(
        self,
        entry_id: UUID,
        new_score: float,
        reason: str,
        actor: str = "system",
    ) -> None:
        """Update the trust score for a registered entry.

        Every change is appended to the trust history for auditability.
        If the entry has children derived from it, their trust is also
        recomputed to reflect the change (cascading update).

        Args:
            entry_id: UUID of the entry to update.
            new_score: New trust score in [0.0, 1.0].
            reason: Human-readable justification (e.g. "source_compromised").
            actor: Component performing the update.

        Raises:
            KeyError: If no provenance record exists for entry_id.
            ValueError: If new_score is outside [0.0, 1.0].
        """
        if entry_id not in self._records:
            raise KeyError(f"No provenance record for entry {entry_id}.")
        if not (0.0 <= new_score <= 1.0):
            raise ValueError(f"trust_score must be in [0, 1], got {new_score}.")

        record = self._records[entry_id]
        old_score = record.trust_score
        record.trust_score = round(new_score, 4)
        record.trust_history.append({
            "trust_score": round(new_score, 4),
            "previous_score": round(old_score, 4),
            "timestamp": _utcnow().isoformat(),
            "reason": reason,
            "actor": actor,
        })

        self._emit(AuditEvent(
            event_type=AuditEventType.TRUST_UPDATED,
            entry_id=entry_id,
            actor=actor,
            payload={"old_score": old_score, "new_score": new_score, "reason": reason},
        ))

        # Cascade: update children whose trust was derived from this entry
        children = [cid for cid, pid in self._parent_map.items() if pid == entry_id]
        for child_id in children:
            if child_id in self._records:
                child_record = self._records[child_id]
                propagated = round(new_score * self.trust_decay, 4)
                if child_record.trust_score > propagated:
                    self.update_trust(
                        child_id,
                        propagated,
                        reason=f"cascade_from_parent_{entry_id}",
                        actor=actor,
                    )

    # ------------------------------------------------------------------
    # Transformation logging
    # ------------------------------------------------------------------

    def record_transformation(
        self,
        entry_id: UUID,
        operation: str,
        details: dict[str, Any] | None = None,
        actor: str = "system",
    ) -> None:
        """Append a transformation event to an entry's provenance record.

        Standard operations: ``chunk``, ``embed``, ``summarize``, ``translate``,
        ``rerank``, ``merge``, ``split``, ``redact``.

        Args:
            entry_id: UUID of the memory entry.
            operation: Name of the transformation.
            details: Structured metadata (model name, chunk size, etc.).
            actor: Component performing the transformation.

        Raises:
            KeyError: If no provenance record exists for entry_id.
        """
        if entry_id not in self._records:
            raise KeyError(f"No provenance record for entry {entry_id}. Register it first.")

        event = {
            "operation": operation,
            "timestamp": _utcnow().isoformat(),
            "actor": actor,
            "details": details or {},
        }
        self._records[entry_id].transformations.append(event)

        self._emit(AuditEvent(
            event_type=AuditEventType.TRANSFORMED,
            entry_id=entry_id,
            actor=actor,
            payload={"operation": operation, "details": details or {}},
        ))

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get(self, entry_id: UUID) -> ProvenanceRecord | None:
        """Retrieve the provenance record for a given entry."""
        return self._records.get(entry_id)

    def get_lineage(self, entry_id: UUID) -> list[ProvenanceRecord]:
        """Walk the parent chain and return the full ancestry as an ordered list.

        The list is ordered from the root ancestor to the given entry:
        ``[root, ..., parent, entry]``.

        Args:
            entry_id: UUID of the entry to trace.

        Returns:
            List of ProvenanceRecords from root to entry. Returns [entry] if
            it has no registered parent.
        """
        chain: list[ProvenanceRecord] = []
        current = entry_id
        visited: set[UUID] = set()

        while current is not None:
            if current in visited:
                logger.warning("Cycle detected in provenance chain at entry %s", current)
                break
            visited.add(current)

            record = self._records.get(current)
            if record:
                chain.append(record)

            current = self._parent_map.get(current)  # type: ignore[assignment]

        chain.reverse()
        return chain

    def all_records(self) -> list[ProvenanceRecord]:
        """Return all registered provenance records."""
        return list(self._records.values())

    def low_trust_entries(self, threshold: float = 0.5) -> list[ProvenanceRecord]:
        """Return records whose trust score is strictly below threshold.

        Args:
            threshold: Trust score cutoff (exclusive). Defaults to 0.5.
        """
        return [r for r in self._records.values() if r.trust_score < threshold]

    def audit_log(self) -> list[AuditEvent]:
        """Return the full append-only audit event log."""
        return list(self._audit_log)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit(self, event: AuditEvent) -> None:
        self._audit_log.append(event)
