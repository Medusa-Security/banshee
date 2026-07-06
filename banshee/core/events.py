from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from datetime import datetime
from banshee.core.types import _utcnow

class EventCategory(str, Enum):
    CONTEXT = "context"
    MEMORY = "memory"
    EXECUTION = "execution"
    PATCH = "patch"
    KNOWLEDGE = "knowledge"

class SecurityEvent(BaseModel):
    """
    An event intercepted by Banshee that requires security evaluation.
    """
    event_id: UUID = Field(default_factory=uuid4)
    category: EventCategory
    action: str = Field(..., description="Specific action being taken (e.g., 'run_command', 'apply_patch')")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Data associated with the event")
    timestamp: datetime = Field(default_factory=_utcnow)
    source: str = Field(default="medusa", description="Origin of the event")
