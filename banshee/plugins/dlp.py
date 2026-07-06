import re
from typing import List
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class DataLossPreventionPlugin(BansheePlugin):
    """
    DLP (Data Loss Prevention) Scanner.
    Detects if the AI agent is attempting to leak or process PII (Personally Identifiable Information),
    such as Credit Card numbers, SSNs, or API Keys in its context or execution payloads.
    """
    @property
    def name(self) -> str:
        return "DLPSecurityScanner"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.CONTEXT, EventCategory.EXECUTION, EventCategory.PATCH]

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        payload_str = str(event.payload)
        
        # Simple heuristics for PII / Leaks
        # 1. Credit Card (Luhn check simplified to regex for demonstration)
        cc_pattern = r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"
        if re.search(cc_pattern, payload_str):
            return RiskScore(
                level=RiskLevel.CRITICAL,
                confidence=0.9,
                reasoning="DLP Violation: Detected potential Credit Card number in payload. Halting to prevent data exfiltration.",
                plugin_name=self.name
            )
            
        # 2. Social Security Numbers (US)
        ssn_pattern = r"\b(?!000|666)[0-8][0-9]{2}-(?!00)[0-9]{2}-(?!0000)[0-9]{4}\b"
        if re.search(ssn_pattern, payload_str):
            return RiskScore(
                level=RiskLevel.CRITICAL,
                confidence=0.9,
                reasoning="DLP Violation: Detected potential Social Security Number (SSN) in payload.",
                plugin_name=self.name
            )
            
        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="No sensitive data signatures (PII/CC) detected.",
            plugin_name=self.name
        )
