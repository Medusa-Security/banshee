"""
Example: Provenance tracking for memory entries.

Demonstrates registering entries, recording transformations,
and identifying low-trust sources.
"""

from banshee.integrity import compute_checksum
from banshee.models import MemoryEntry
from banshee.provenance import ProvenanceTracker


def main() -> None:
    tracker = ProvenanceTracker()

    # Ingest a document from a trusted source
    trusted_entry = MemoryEntry(
        content="LLMs are trained on large corpora using self-supervised objectives.",
        source="https://trusted-journal.org/paper-001",
        checksum=compute_checksum("LLMs are trained on large corpora using self-supervised objectives."),
    )
    tracker.register(trusted_entry, source_uri=trusted_entry.source, trust_score=0.95)
    tracker.record_transformation(trusted_entry.id, "chunk", {"chunk_size": 512, "overlap": 50})
    tracker.record_transformation(trusted_entry.id, "embed", {"model": "text-embedding-3-small"})

    # Ingest from an untrusted scrape
    untrusted_entry = MemoryEntry(
        content="Some scraped content from an unknown source.",
        source="https://random-forum.io/post/12345",
    )
    tracker.register(untrusted_entry, source_uri=untrusted_entry.source, trust_score=0.3)

    # Report
    print("\n=== Provenance Report ===")
    for record in tracker.all_records():
        print(f"\n  Entry:       {record.entry_id}")
        print(f"  Source:      {record.source_uri}")
        print(f"  Trust Score: {record.trust_score}")
        print(f"  Transforms:  {len(record.transformations)}")
        for t in record.transformations:
            print(f"    - {t['operation']} at {t['timestamp']}")

    low_trust = tracker.low_trust_entries(threshold=0.5)
    if low_trust:
        print(f"\n⚠  {len(low_trust)} low-trust entry/entries detected. Review before use.")


if __name__ == "__main__":
    main()
