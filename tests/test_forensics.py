"""
Tests for banshee.forensics module.
"""

import pytest
from banshee.forensics import ForensicAnalyzer, MemoryRecovery
from banshee.integrity import IntegrityVerifier, compute_checksum
from banshee.models import AttackType, IntegrityStatus, MemoryEntry, RiskLevel


class TestForensicAnalyzer:
    def _make_entries_and_reports(self):
        clean = MemoryEntry(content="clean", checksum=compute_checksum("clean"))
        tampered = MemoryEntry(
            content="modified",
            checksum=compute_checksum("original"),
            source="https://compromised.example.com",
        )
        verifier = IntegrityVerifier()
        reports = verifier.check_store([clean, tampered])
        return [clean, tampered], reports

    def test_tampered_entry_produces_critical_finding(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        critical = [f for f in incident.findings if f.severity == RiskLevel.CRITICAL]
        assert len(critical) >= 1
        assert any(f.attack_type == AttackType.DATA_POISONING for f in critical)

    def test_suspicion_score_higher_for_tampered(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        tampered_id = str(entries[1].id)
        clean_id = str(entries[0].id)
        scores = incident.suspicion_scores
        if tampered_id in scores and clean_id in scores:
            assert scores[tampered_id] > scores.get(clean_id, 0.0)

    def test_source_clusters_group_by_source(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        assert isinstance(incident.source_clusters, dict)
        # The tampered entry has a source, so it should appear
        assert any("compromised" in k for k in incident.source_clusters)

    def test_timeline_is_chronological(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        timestamps = [e.timestamp for e in incident.timeline]
        assert timestamps == sorted(timestamps)

    def test_highest_risk_entries_returns_sorted(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        top = incident.highest_risk_entries(n=5)
        if len(top) >= 2:
            scores = [s for _, s in top]
            assert scores == sorted(scores, reverse=True)

    def test_total_findings_counts_correctly(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        assert incident.total_findings == len(incident.findings)

    def test_suspected_attack_types_present(self):
        entries, reports = self._make_entries_and_reports()
        analyzer = ForensicAnalyzer()
        incident = analyzer.build_incident_report(entries, reports, [])
        assert isinstance(incident.suspected_attack_types, list)


class TestMemoryRecovery:
    def test_quarantine_separates_tampered(self):
        clean = MemoryEntry(content="clean", integrity_status=IntegrityStatus.VERIFIED)
        tampered = MemoryEntry(content="bad", integrity_status=IntegrityStatus.TAMPERED)
        corrupted = MemoryEntry(content="corrupt", integrity_status=IntegrityStatus.CORRUPTED)

        recovery = MemoryRecovery()
        clean_list, quarantined = recovery.quarantine_tampered([clean, tampered, corrupted])

        assert len(clean_list) == 1
        assert len(quarantined) == 2
        assert clean in clean_list
        assert tampered in quarantined
        assert corrupted in quarantined

    def test_restore_from_backup_uses_resolver(self):
        bad = MemoryEntry(content="bad", integrity_status=IntegrityStatus.TAMPERED)
        good = MemoryEntry(content="good", integrity_status=IntegrityStatus.VERIFIED)

        def resolver(entry: MemoryEntry) -> MemoryEntry | None:
            return good  # always return backup

        recovery = MemoryRecovery()
        restored, unrecoverable = recovery.restore_from_backup([bad], resolver)

        assert len(restored) == 1
        assert restored[0] is good
        assert len(unrecoverable) == 0

    def test_restore_from_backup_handles_missing(self):
        bad = MemoryEntry(content="bad", integrity_status=IntegrityStatus.TAMPERED)

        def resolver(entry: MemoryEntry) -> MemoryEntry | None:
            return None  # no backup available

        recovery = MemoryRecovery()
        restored, unrecoverable = recovery.restore_from_backup([bad], resolver)

        assert len(restored) == 0
        assert len(unrecoverable) == 1

    def test_purge_returns_count(self):
        entries = [MemoryEntry(content=f"bad {i}") for i in range(5)]
        recovery = MemoryRecovery()
        count = recovery.purge(entries)
        assert count == 5
