"""
MemoryScanner — orchestrates a full security scan of an AI memory store.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Sequence

from banshee.integrity import IntegrityVerifier
from banshee.models import ForensicFinding, IntegrityReport, MemoryEntry, RiskLevel
from banshee.security.detector import PoisoningDetector

logger = logging.getLogger(__name__)


@dataclass
class ScanReport:
    """Aggregated results from a full memory store security scan."""

    total_entries: int = 0
    integrity_reports: list[IntegrityReport] = field(default_factory=list)
    forensic_findings: list[ForensicFinding] = field(default_factory=list)

    @property
    def critical_findings(self) -> list[ForensicFinding]:
        return [f for f in self.forensic_findings if f.severity == RiskLevel.CRITICAL]

    @property
    def high_findings(self) -> list[ForensicFinding]:
        return [f for f in self.forensic_findings if f.severity == RiskLevel.HIGH]

    @property
    def tampered_count(self) -> int:
        from banshee.models import IntegrityStatus
        return sum(1 for r in self.integrity_reports if r.status == IntegrityStatus.TAMPERED)

    def summary(self) -> dict[str, int]:
        return {
            "total_entries": self.total_entries,
            "tampered": self.tampered_count,
            "critical_findings": len(self.critical_findings),
            "high_findings": len(self.high_findings),
            "total_findings": len(self.forensic_findings),
        }


class MemoryScanner:
    """Runs a comprehensive security scan over an AI memory store.

    Combines integrity verification with poisoning detection to produce a
    unified ScanReport.

    Example:
        >>> scanner = MemoryScanner()
        >>> report = scanner.scan(entries)
        >>> print(report.summary())
    """

    def __init__(
        self,
        verifier: IntegrityVerifier | None = None,
        detector: PoisoningDetector | None = None,
    ) -> None:
        self.verifier = verifier or IntegrityVerifier()
        self.detector = detector or PoisoningDetector()

    def scan(self, entries: Sequence[MemoryEntry]) -> ScanReport:
        """Perform a full security scan of the provided memory entries.

        Args:
            entries: The memory store entries to scan.

        Returns:
            A ScanReport containing integrity and forensic results.
        """
        logger.info("Starting memory scan on %d entries.", len(entries))

        report = ScanReport(total_entries=len(entries))
        report.integrity_reports = self.verifier.check_store(list(entries))
        report.forensic_findings = self.detector.scan_entries(entries)

        summary = report.summary()
        logger.info("Scan complete. Summary: %s", summary)

        return report
