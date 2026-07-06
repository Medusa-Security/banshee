import re
from typing import List
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class NetworkSecurityPlugin(BansheePlugin):
    """
    Prevents Server-Side Request Forgery (SSRF) and malicious network access.
    Blocks AI agents from accessing cloud metadata endpoints, localhost, or internal IPs.
    """
    @property
    def name(self) -> str:
        return "NetworkSecurityProtector"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.EXECUTION, EventCategory.KNOWLEDGE]

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        payload_str = str(event.payload).lower()
        
        # Cloud Metadata SSRF endpoints
        if "169.254.169.254" in payload_str or "metadata.google.internal" in payload_str:
            return RiskScore(
                level=RiskLevel.CRITICAL,
                confidence=1.0,
                reasoning="SSRF Attempt: Agent attempted to access cloud instance metadata.",
                plugin_name=self.name
            )
            
        # Localhost/Loopback bypass attempts
        loopback_patterns = [r"localhost", r"127\.0\.0\.1", r"0\.0\.0\.0", r"::1"]
        for pattern in loopback_patterns:
            if re.search(pattern, payload_str):
                return RiskScore(
                    level=RiskLevel.HIGH,
                    confidence=0.9,
                    reasoning=f"SSRF Attempt: Agent attempted to access local loopback address.",
                    plugin_name=self.name
                )
                
        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="No malicious network patterns detected.",
            plugin_name=self.name
        )
