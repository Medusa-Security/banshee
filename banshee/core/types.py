from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from datetime import datetime, timezone

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)

class RiskLevel(str, Enum):
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

class SecurityAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    QUARANTINE = "quarantine"
    REQUIRES_HUMAN = "requires_human"

class RiskScore(BaseModel):
    level: RiskLevel
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this assessment (0-1)")
    reasoning: str
    plugin_name: str

class SecurityDecision(BaseModel):
    action: SecurityAction
    aggregate_risk: RiskLevel
    aggregate_confidence: float
    reasons: list[str]
    timestamp: datetime = Field(default_factory=_utcnow)
