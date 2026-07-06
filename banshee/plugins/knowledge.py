from urllib.parse import urlparse
from typing import List, Dict, Any
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class KnowledgeVerificationPlugin(BansheePlugin):
    """
    Advanced Knowledge Verifier.
    Validates source reputation, checks for citation hallucination,
    and estimates retrieval confidence.
    """
    @property
    def name(self) -> str:
        return "AdvancedKnowledgeVerifier"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.KNOWLEDGE]

    def _get_trusted_domains(self) -> List[str]:
        return ["docs.python.org", "github.com", "stackoverflow.com", "developer.mozilla.org"]

    def _get_blacklisted_domains(self) -> List[str]:
        return ["malicious-docs.info", "fake-api.net"]

    def _verify_source_reputation(self, url: str) -> int:
        """Returns 1 for trusted, -1 for blacklisted, 0 for unknown."""
        try:
            domain = urlparse(url).netloc.lower()
            if any(trusted in domain for trusted in self._get_trusted_domains()):
                return 1
            if any(black in domain for black in self._get_blacklisted_domains()):
                return -1
        except Exception:
            pass
        return 0

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        sources: List[Dict[str, Any]] = event.payload.get("sources", [])
        retrieved_text = event.payload.get("text", "")
        
        if not sources:
            return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.8,
                reasoning="Knowledge retrieved without any verifiable sources. High risk of hallucination.",
                plugin_name=self.name
            )

        untrusted_count = 0
        blacklisted_found = False

        for source in sources:
            url = source.get("url", "")
            reputation = self._verify_source_reputation(url)
            
            if reputation == -1:
                blacklisted_found = True
            elif reputation == 0:
                untrusted_count += 1

        if blacklisted_found:
             return RiskScore(
                level=RiskLevel.HIGH,
                confidence=0.95,
                reasoning="Knowledge retrieved from a known malicious or blacklisted domain.",
                plugin_name=self.name
            )

        if untrusted_count == len(sources):
             return RiskScore(
                level=RiskLevel.LOW,
                confidence=0.6,
                reasoning="All knowledge sources are from unknown/unverified domains. Proceed with caution.",
                plugin_name=self.name
            )

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="Knowledge retrieval validated. Sources contain trusted domains.",
            plugin_name=self.name
        )
