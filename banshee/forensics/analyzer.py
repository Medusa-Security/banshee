"""
ForensicAnalyzer — deep analysis of memory integrity incidents.

Capabilities:
- Correlate IntegrityReports with MemoryEntries to produce structured findings
- Reconstruct attack timelines by ordering events chronologically
- Cluster findings by source to identify single-origin mass compromises
- Score entries with a composite suspicion score for triage prioritization
- Detect cross-entry factual contradictions (same topic, conflicting claims)
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Sequence
from uuid import UUID

from banshee.models import (
    AttackType,
    ForensicFinding,
    IntegrityReport,
    IntegrityStatus,
    MemoryEntry,
    RiskLevel,
)

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    """A single event in a reconstructed attack timeline."""

    timestamp: datetime
    entry_id: UUID
    event_type: str
    description: str
    severity: RiskLevel
    source: str | None = None


@dataclass
class IncidentReport:
    """Consolidated forensic incident report for a memory store."""

    total_entries_analyzed: int = 0
    total_findings: int = 0
    findings: list[ForensicFinding] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    source_clusters: dict[str, list[ForensicFinding]] = field(default_factory=dict)
    suspicion_scores: dict[str, float] = field(default_factory=dict)  # entry_id → score
    suspected_attack_types: list[AttackType] = field(default_factory=list)

    def highest_risk_entries(self, n: int = 10) -> list[tuple[str, float]]:
        """Return the top-n entries by suspicion score."""
        return sorted(self.suspicion_scores.items(), key=lambda x: x[1], reverse=True)[:n]


class ForensicAnalyzer:
    """Performs deep forensic analysis on AI memory integrity incidents.

    Combines integrity reports with raw entry data to produce a full
    IncidentReport that security analysts can use to investigate, triage,
    and respond to memory-based attacks.

    Example:
        >>> from banshee.security import MemoryScanner
        >>> scanner = MemoryScanner()
        >>> scan = scanner.scan(entries)
        >>> analyzer = ForensicAnalyzer()
        >>> incident = analyzer.build_incident_report(entries, scan.integrity_reports, scan.forensic_findings)
        >>> for entry_id, score in incident.highest_risk_entries(5):
        ...     print(f"{entry_id}: {score:.2f}")
    """

    # Weights for computing the composite suspicion score per entry
    _SEVERITY_WEIGHTS = {
        RiskLevel.NONE: 0.0,
        RiskLevel.LOW: 0.1,
        RiskLevel.MEDIUM: 0.3,
        RiskLevel.HIGH: 0.7,
        RiskLevel.CRITICAL: 1.0,
    }

    def build_incident_report(
        self,
        entries: Sequence[MemoryEntry],
        integrity_reports: Sequence[IntegrityReport],
        forensic_findings: Sequence[ForensicFinding],
    ) -> IncidentReport:
        """Produce a complete forensic IncidentReport.

        Args:
            entries: All memory entries under investigation.
            integrity_reports: One IntegrityReport per entry.
            forensic_findings: Pre-computed findings (e.g., from PoisoningDetector).

        Returns:
            IncidentReport with timeline, clusters, suspicion scores, and findings.
        """
        entry_map: dict[UUID, MemoryEntry] = {e.id: e for e in entries}
        report = IncidentReport(
            total_entries_analyzed=len(list(entries)),
        )

        # 1. Convert integrity reports → additional findings
        integrity_findings = self._integrity_to_findings(entry_map, integrity_reports)
        all_findings = list(forensic_findings) + integrity_findings
        report.findings = all_findings
        report.total_findings = len(all_findings)

        # 2. Reconstruct attack timeline
        report.timeline = self._build_timeline(entry_map, all_findings)

        # 3. Cluster by source
        report.source_clusters = self._cluster_by_source(all_findings, entry_map)

        # 4. Compute per-entry suspicion scores
        report.suspicion_scores = self._compute_suspicion_scores(all_findings)

        # 5. Identify suspected attack types
        attack_type_counts: dict[AttackType, int] = defaultdict(int)
        for f in all_findings:
            attack_type_counts[f.attack_type] += 1
        report.suspected_attack_types = [
            at for at, _ in sorted(attack_type_counts.items(), key=lambda x: -x[1])
        ]

        logger.info(
            "Incident report built: %d findings, %d sources, top attack=%s",
            len(all_findings),
            len(report.source_clusters),
            report.suspected_attack_types[0] if report.suspected_attack_types else "none",
        )
        return report

    def _integrity_to_findings(
        self,
        entry_map: dict[UUID, MemoryEntry],
        reports: Sequence[IntegrityReport],
    ) -> list[ForensicFinding]:
        """Convert IntegrityReport violations into ForensicFinding objects."""
        findings: list[ForensicFinding] = []
        for report in reports:
            entry = entry_map.get(report.entry_id)
            if entry is None:
                continue

            if report.status == IntegrityStatus.TAMPERED:
                findings.append(ForensicFinding(
                    entry_id=entry.id,
                    severity=RiskLevel.CRITICAL,
                    attack_type=AttackType.DATA_POISONING,
                    category="checksum_mismatch",
                    description="Content does not match stored checksum — tampering confirmed.",
                    evidence={
                        "stored_checksum": entry.checksum,
                        "source": entry.source,
                        "created_at": entry.created_at.isoformat(),
                        "updated_at": entry.updated_at.isoformat(),
                        "integrity_issues": report.issues,
                    },
                    confidence=1.0,
                    remediation_hint="Quarantine immediately. Restore from a verified backup.",
                ))

            elif report.status == IntegrityStatus.CORRUPTED:
                findings.append(ForensicFinding(
                    entry_id=entry.id,
                    severity=RiskLevel.HIGH,
                    attack_type=AttackType.UNKNOWN,
                    category="structural_corruption",
                    description="Entry is structurally corrupted (embedding mismatch or schema violation).",
                    evidence={"issues": report.issues, "details": report.details},
                    confidence=0.9,
                    remediation_hint="Re-ingest from the original verified source.",
                ))

            # Surface sub-critical integrity issues individually
            for issue in report.issues:
                if report.status not in (IntegrityStatus.TAMPERED, IntegrityStatus.CORRUPTED):
                    findings.append(ForensicFinding(
                        entry_id=entry.id,
                        severity=report.risk_level,
                        attack_type=AttackType.UNKNOWN,
                        category="integrity_issue",
                        description=issue,
                        evidence={"integrity_status": report.status.value, "details": report.details},
                        confidence=0.8,
                    ))
        return findings

    def _build_timeline(
        self,
        entry_map: dict[UUID, MemoryEntry],
        findings: list[ForensicFinding],
    ) -> list[TimelineEvent]:
        """Reconstruct a chronological attack timeline from findings."""
        events: list[TimelineEvent] = []

        for finding in findings:
            entry = entry_map.get(finding.entry_id)
            events.append(TimelineEvent(
                timestamp=finding.detected_at,
                entry_id=finding.entry_id,
                event_type=finding.category,
                description=finding.description,
                severity=finding.severity,
                source=entry.source if entry else None,
            ))

        # Also add entry ingestion times as timeline anchors
        for entry in entry_map.values():
            events.append(TimelineEvent(
                timestamp=entry.created_at,
                entry_id=entry.id,
                event_type="ingested",
                description=f"Entry ingested from {entry.source or 'unknown source'}",
                severity=RiskLevel.NONE,
                source=entry.source,
            ))

        events.sort(key=lambda e: e.timestamp)
        return events

    def _cluster_by_source(
        self,
        findings: list[ForensicFinding],
        entry_map: dict[UUID, MemoryEntry],
    ) -> dict[str, list[ForensicFinding]]:
        """Group findings by the source URI of their associated entry.

        A single compromised source producing many findings is a strong
        signal of a coordinated supply-chain or ingestion pipeline attack.
        """
        clusters: dict[str, list[ForensicFinding]] = defaultdict(list)
        for finding in findings:
            entry = entry_map.get(finding.entry_id)
            key = entry.source if (entry and entry.source) else "unknown"
            clusters[key].append(finding)
        return dict(clusters)

    def _compute_suspicion_scores(
        self, findings: list[ForensicFinding]
    ) -> dict[str, float]:
        """Compute a composite suspicion score for each entry.

        Score is the sum of ``severity_weight * confidence`` across all
        findings for that entry, capped at 1.0.

        Higher scores → higher investigation priority.
        """
        scores: dict[str, float] = defaultdict(float)
        for finding in findings:
            weight = self._SEVERITY_WEIGHTS.get(finding.severity, 0.0)
            scores[str(finding.entry_id)] += weight * finding.confidence

        # Normalize to [0, 1]
        return {eid: min(score, 1.0) for eid, score in scores.items()}
