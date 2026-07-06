import time
from typing import List, Dict, collections
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class BehavioralSecurityPlugin(BansheePlugin):
    """
    Tracks behavioral anomalies over time to prevent looping, 
    denial-of-wallet/compute attacks, and erratic agent behavior.
    """
    def __init__(self, max_events_per_minute: int = 100):
        self.max_events_per_minute = max_events_per_minute
        # Simple in-memory tracker: event_category -> list of timestamps
        self.history: Dict[EventCategory, List[float]] = {}
        super().__init__()

    @property
    def name(self) -> str:
        return "BehavioralAnomalyDetector"

    @property
    def supported_categories(self) -> List[EventCategory]:
        # Monitors all event categories
        return [c for c in EventCategory]

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        current_time = time.time()
        category = event.category
        
        if category not in self.history:
            self.history[category] = []
            
        # Append current event timestamp
        self.history[category].append(current_time)
        
        # Clean up events older than 60 seconds
        cutoff = current_time - 60.0
        self.history[category] = [ts for ts in self.history[category] if ts > cutoff]
        
        event_count = len(self.history[category])
        
        # Check for Denial of Compute / Looping attacks
        if event_count > self.max_events_per_minute:
            return RiskScore(
                level=RiskLevel.HIGH,
                confidence=0.9,
                reasoning=f"Behavioral Anomaly: Agent is looping or spamming events. {event_count} {category.name if hasattr(category, 'name') else category} events in the last 60 seconds (Limit: {self.max_events_per_minute}).",
                plugin_name=self.name
            )
            
        # Check for specific behavioral signatures
        if category == EventCategory.EXECUTION and event_count > (self.max_events_per_minute // 2):
            return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.8,
                reasoning="Behavioral Anomaly: Unusually high frequency of shell command executions. Potential brute-force or runaway agent.",
                plugin_name=self.name
            )

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="Behavioral metrics nominal.",
            plugin_name=self.name
        )
