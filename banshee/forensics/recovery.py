"""
MemoryRecovery — strategies for recovering from compromised memory stores.
"""

from __future__ import annotations

import logging
from typing import Callable, Sequence

from banshee.models import IntegrityStatus, MemoryEntry

logger = logging.getLogger(__name__)


class MemoryRecovery:
    """Provides recovery strategies for compromised AI memory stores.

    Recovery strategies:
    - **Quarantine**: Isolate tampered or suspicious entries for manual review.
    - **Purge**: Remove entries that cannot be recovered.
    - **Restore**: Replace entries from a verified backup source.

    Example:
        >>> recovery = MemoryRecovery()
        >>> clean, quarantined = recovery.quarantine_tampered(entries)
    """

    def quarantine_tampered(
        self, entries: Sequence[MemoryEntry]
    ) -> tuple[list[MemoryEntry], list[MemoryEntry]]:
        """Separate verified entries from those flagged as tampered or unverified.

        Args:
            entries: The full set of memory entries.

        Returns:
            Tuple of (clean_entries, quarantined_entries).
        """
        clean: list[MemoryEntry] = []
        quarantined: list[MemoryEntry] = []

        for entry in entries:
            if entry.integrity_status in (IntegrityStatus.TAMPERED, IntegrityStatus.CORRUPTED):
                quarantined.append(entry)
                logger.warning("Quarantined entry %s (status: %s)", entry.id, entry.integrity_status)
            else:
                clean.append(entry)

        logger.info(
            "Quarantine complete. Clean: %d, Quarantined: %d", len(clean), len(quarantined)
        )
        return clean, quarantined

    def restore_from_backup(
        self,
        entries: Sequence[MemoryEntry],
        backup_resolver: Callable[[MemoryEntry], MemoryEntry | None],
    ) -> tuple[list[MemoryEntry], list[MemoryEntry]]:
        """Attempt to restore compromised entries from a backup source.

        Args:
            entries: Memory entries to restore (typically the quarantined list).
            backup_resolver: A callable that takes a compromised MemoryEntry and
                returns a clean replacement, or None if unavailable.

        Returns:
            Tuple of (restored_entries, unrecoverable_entries).
        """
        restored: list[MemoryEntry] = []
        unrecoverable: list[MemoryEntry] = []

        for entry in entries:
            replacement = backup_resolver(entry)
            if replacement is not None:
                restored.append(replacement)
                logger.info("Restored entry %s from backup.", entry.id)
            else:
                unrecoverable.append(entry)
                logger.error("No backup available for entry %s. Marking unrecoverable.", entry.id)

        return restored, unrecoverable

    def purge(self, entries: Sequence[MemoryEntry]) -> int:
        """Log and count entries being purged from a memory store.

        This method does not modify any persistent store directly; the caller
        is responsible for removing the returned entries from their store.

        Args:
            entries: Entries to purge.

        Returns:
            Count of purged entries.
        """
        count = len(list(entries))
        logger.warning("Purging %d unrecoverable memory entries.", count)
        return count
