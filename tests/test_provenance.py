"""
Tests for banshee.provenance module.
"""

import uuid
import pytest
from banshee.models import AuditEventType, MemoryEntry
from banshee.provenance import ProvenanceTracker


class TestProvenanceTracker:
    def _entry(self, content: str = "test content") -> MemoryEntry:
        return MemoryEntry(content=content)

    def test_register_creates_record(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        record = tracker.register(entry, source_uri="https://example.com")
        assert record.entry_id == entry.id
        assert record.source_uri == "https://example.com"

    def test_get_returns_registered_record(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        tracker.register(entry)
        record = tracker.get(entry.id)
        assert record is not None
        assert record.entry_id == entry.id

    def test_get_returns_none_for_unknown(self):
        tracker = ProvenanceTracker()
        assert tracker.get(uuid.uuid4()) is None

    def test_record_transformation(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        tracker.register(entry)
        tracker.record_transformation(entry.id, operation="chunk", details={"size": 512})
        record = tracker.get(entry.id)
        assert len(record.transformations) == 1
        assert record.transformations[0]["operation"] == "chunk"
        assert record.transformations[0]["details"]["size"] == 512

    def test_record_transformation_raises_for_unknown(self):
        tracker = ProvenanceTracker()
        with pytest.raises(KeyError):
            tracker.record_transformation(uuid.uuid4(), operation="embed")

    def test_low_trust_entries(self):
        tracker = ProvenanceTracker()
        high = self._entry("high trust")
        low = self._entry("low trust")
        tracker.register(high, trust_score=0.9)
        tracker.register(low, trust_score=0.2)
        result = tracker.low_trust_entries(threshold=0.5)
        assert len(result) == 1
        assert result[0].entry_id == low.id

    def test_all_records(self):
        tracker = ProvenanceTracker()
        for i in range(3):
            tracker.register(self._entry(f"entry {i}"))
        assert len(tracker.all_records()) == 3

    def test_trust_propagation_caps_child_trust(self):
        """Child trust cannot exceed parent_trust * decay."""
        tracker = ProvenanceTracker(trust_decay=0.8)
        parent = self._entry("parent")
        child = self._entry("child")
        tracker.register(parent, trust_score=0.6)
        tracker.register(child, trust_score=1.0, parent_id=parent.id)  # request 1.0

        child_record = tracker.get(child.id)
        assert child_record.trust_score <= 0.6 * 0.8 + 1e-9  # float tolerance

    def test_trust_update_creates_history(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        tracker.register(entry, trust_score=0.9)
        tracker.update_trust(entry.id, 0.3, reason="source_compromised")
        record = tracker.get(entry.id)
        assert record.trust_score == 0.3
        assert len(record.trust_history) == 2  # initial + update
        assert record.trust_history[1]["reason"] == "source_compromised"
        assert record.trust_history[1]["previous_score"] == 0.9

    def test_trust_update_cascades_to_children(self):
        """Lowering a parent's trust should propagate to its children."""
        tracker = ProvenanceTracker(trust_decay=0.9)
        parent = self._entry("parent")
        child = self._entry("child")
        tracker.register(parent, trust_score=1.0)
        tracker.register(child, trust_score=0.9, parent_id=parent.id)

        # Compromise the parent source
        tracker.update_trust(parent.id, 0.1, reason="source_compromised")

        child_record = tracker.get(child.id)
        assert child_record.trust_score <= 0.1 * 0.9 + 1e-9

    def test_get_lineage_returns_chain(self):
        tracker = ProvenanceTracker()
        root = self._entry("root")
        child = self._entry("child")
        grandchild = self._entry("grandchild")

        tracker.register(root)
        tracker.register(child, parent_id=root.id)
        tracker.register(grandchild, parent_id=child.id)

        lineage = tracker.get_lineage(grandchild.id)
        assert len(lineage) == 3
        assert lineage[0].entry_id == root.id
        assert lineage[-1].entry_id == grandchild.id

    def test_audit_log_records_events(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        tracker.register(entry)
        tracker.record_transformation(entry.id, "embed")
        tracker.update_trust(entry.id, 0.5, reason="test")

        log = tracker.audit_log()
        event_types = [e.event_type for e in log]
        assert AuditEventType.INGESTED in event_types
        assert AuditEventType.TRANSFORMED in event_types
        assert AuditEventType.TRUST_UPDATED in event_types

    def test_invalid_trust_decay_raises(self):
        with pytest.raises(ValueError):
            ProvenanceTracker(trust_decay=0.0)

    def test_update_trust_invalid_score_raises(self):
        tracker = ProvenanceTracker()
        entry = self._entry()
        tracker.register(entry)
        with pytest.raises(ValueError):
            tracker.update_trust(entry.id, 1.5, reason="test")
