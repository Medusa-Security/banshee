import hashlib
from typing import List, Dict, Any
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class AdvancedMemorySecurityPlugin(BansheePlugin):
    """
    Advanced Memory Protector.
    Validates cryptographic integrity of memory nodes and evaluates provenance
    chains to prevent memory injection attacks.
    """
    @property
    def name(self) -> str:
        return "AdvancedMemoryProtector"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.MEMORY]

    def _verify_checksum(self, content: str, expected_hash: str) -> bool:
        if not content and not expected_hash:
            return True
        actual_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
        return actual_hash == expected_hash

    def _evaluate_trust_score(self, source: str) -> float:
        """Evaluate the inherent trust of a memory source."""
        trusted_sources = ["system", "verified_user", "internal_agent"]
        if source in trusted_sources:
            return 1.0
        if source == "unverified_user" or source == "external_api":
            return 0.5
        return 0.1

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        operation = event.action
        payload = event.payload
        
        if operation in ["read", "load"]:
            memory_nodes: List[Dict[str, Any]] = payload.get("nodes", [])
            for node in memory_nodes:
                content = node.get("content", "")
                checksum = node.get("checksum", "")
                source = node.get("source", "unknown")
                
                # 1. Integrity Check
                if checksum and not self._verify_checksum(content, checksum):
                    return RiskScore(
                        level=RiskLevel.CRITICAL,
                        confidence=0.99,
                        reasoning=f"Cryptographic integrity failure on memory node from source: {source}. Memory tampered.",
                        plugin_name=self.name
                    )
                
                # 2. Provenance Trust Scoring
                trust_score = self._evaluate_trust_score(source)
                if trust_score < 0.3:
                    return RiskScore(
                        level=RiskLevel.HIGH,
                        confidence=0.8,
                        reasoning=f"Memory node injected from untrusted source: {source}.",
                        plugin_name=self.name
                    )

        if operation == "store":
            content = payload.get("content", "")
            checksum = payload.get("checksum", "")
            
            # Enforce cryptographic tracking
            if content and not checksum:
                return RiskScore(
                    level=RiskLevel.MEDIUM,
                    confidence=0.9,
                    reasoning="Memory stored without a cryptographic checksum. Breaks provenance chain.",
                    plugin_name=self.name
                )

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.95,
            reasoning="Memory integrity and provenance validated.",
            plugin_name=self.name
        )
