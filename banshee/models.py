"""
Core data models shared across BANSHEE modules.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class IntegrityStatus(str, Enum):
    """Possible integrity states for a memory entry."""

    VERIFIED = "verified"
    TAMPERED = "tampered"
    UNVERIFIED = "unverified"
    CORRUPTED = "corrupted"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk severity levels, ordered from lowest to highest."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __gt__(self, other: "RiskLevel") -> bool:
        order = list(RiskLevel)
        return order.index(self) > order.index(other)

    def __ge__(self, other: "RiskLevel") -> bool:
        return self == other or self > other


class AttackType(str, Enum):
    """Known categories of adversarial attacks against AI memory."""

    PROMPT_INJECTION = "prompt_injection"
    DATA_POISONING = "data_poisoning"
    BACKDOOR = "backdoor"
    MEMBERSHIP_INFERENCE = "membership_inference"
    EXFILTRATION = "exfiltration"
    ROLE_HIJACK = "role_hijack"
    TOKEN_INJECTION = "token_injection"
    UNICODE_OBFUSCATION = "unicode_obfuscation"
    FACTUAL_CORRUPTION = "factual_corruption"
    EMBEDDING_INVERSION = "embedding_inversion"
    UNKNOWN = "unknown"


class AuditEventType(str, Enum):
    """Types of events recorded in the audit log."""

    INGESTED = "ingested"
    VERIFIED = "verified"
    TAMPER_DETECTED = "tamper_detected"
    QUARANTINED = "quarantined"
    RESTORED = "restored"
    PURGED = "purged"
    TRANSFORMED = "transformed"
    TRUST_UPDATED = "trust_updated"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"


# ---------------------------------------------------------------------------
# Core data models
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MemoryEntry(BaseModel):
    """Represents a single entry in an AI memory store."""

    id: UUID = Field(default_factory=uuid4)
    content: str = Field(..., description="Raw text or serialized content of the memory")
    embedding: list[float] | None = Field(default=None, description="Vector embedding of the content")
    metadata: dict[str, Any] = Field(default_factory=dict)
    source: str | None = Field(default=None, description="Origin URI or identifier")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    checksum: str | None = Field(default=None, description="Content hash for integrity verification")
    integrity_status: IntegrityStatus = Field(default=IntegrityStatus.UNVERIFIED)
    tags: list[str] = Field(default_factory=list, description="Free-form tags for filtering and grouping")

    model_config = {"validate_assignment": True}


class IntegrityReport(BaseModel):
    """Result of an integrity check on a memory entry."""

    entry_id: UUID
    status: IntegrityStatus
    risk_level: RiskLevel = RiskLevel.NONE
    issues: list[str] = Field(default_factory=list)
    checked_at: datetime = Field(default_factory=_utcnow)
    details: dict[str, Any] = Field(default_factory=dict)


class ProvenanceRecord(BaseModel):
    """Tracks origin and transformation history of a memory entry."""

    entry_id: UUID
    source_uri: str | None = None
    ingested_at: datetime = Field(default_factory=_utcnow)
    transformations: list[dict[str, Any]] = Field(default_factory=list)
    author: str | None = None
    trust_score: float = Field(default=1.0, ge=0.0, le=1.0)
    trust_history: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Append-only log of trust score changes with timestamps and reasons",
    )


class ForensicFinding(BaseModel):
    """A finding produced by memory forensic analysis."""

    finding_id: UUID = Field(default_factory=uuid4)
    entry_id: UUID
    severity: RiskLevel
    attack_type: AttackType = AttackType.UNKNOWN
    category: str = Field(..., description="Sub-category label for the finding")
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    detected_at: datetime = Field(default_factory=_utcnow)
    remediation_hint: str | None = None
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Detector confidence score (0.0 = low, 1.0 = high)",
    )


class AuditEvent(BaseModel):
    """Immutable event record for the append-only audit log."""

    event_id: UUID = Field(default_factory=uuid4)
    event_type: AuditEventType
    entry_id: UUID | None = None
    actor: str = Field(default="system", description="Component or user that triggered the event")
    timestamp: datetime = Field(default_factory=_utcnow)
    payload: dict[str, Any] = Field(default_factory=dict)


class MemoryStoreStats(BaseModel):
    """Aggregate statistics for a memory store snapshot."""

    total_entries: int = 0
    verified: int = 0
    tampered: int = 0
    unverified: int = 0
    corrupted: int = 0
    unknown: int = 0
    with_embeddings: int = 0
    with_provenance: int = 0
    mean_content_length: float = 0.0
    computed_at: datetime = Field(default_factory=_utcnow)
