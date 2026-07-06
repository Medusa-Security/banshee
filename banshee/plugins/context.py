import re
import math
from typing import List
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel

class ContextValidationPlugin(BansheePlugin):
    """
    Advanced Context Validator.
    Replaces static string matching with entropy analysis, structural checks,
    and simulated LLM heuristic checks for prompt injection.
    """
    @property
    def name(self) -> str:
        return "AdvancedContextValidator"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.CONTEXT]

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy to detect heavily encoded or random strings."""
        if not text:
            return 0.0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum(p * math.log(p) / math.log(2.0) for p in prob)
        return entropy

    def _detect_obfuscation(self, prompt: str) -> bool:
        """Detect base64, hex encoding, or unusual character densities."""
        b64_pattern = re.compile(r'(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')
        hex_pattern = re.compile(r'(?:[0-9a-fA-F]{2}\s*){10,}')
        
        if b64_pattern.search(prompt) or hex_pattern.search(prompt):
            return True
        return False

    def _structural_analysis(self, prompt: str) -> RiskScore:
        """Analyze structural anomalies commonly found in prompt injections."""
        prompt_lower = prompt.lower()
        
        # Look for role-playing transitions
        if "you are now" in prompt_lower and "ignore" in prompt_lower:
             return RiskScore(
                level=RiskLevel.HIGH,
                confidence=0.90,
                reasoning="Structural anomaly: Role-playing transition detected with overriding instructions.",
                plugin_name=self.name
            )
            
        # Check for context window overflow attempts (simulated by excessive length + repeated patterns)
        if len(prompt) > 10000 and len(set(prompt)) < 50:
             return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.85,
                reasoning="Structural anomaly: Potential token smashing or context overflow attack.",
                plugin_name=self.name
            )
            
        return None

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        prompt = event.payload.get("prompt", "")
        
        if not prompt:
             return RiskScore(level=RiskLevel.NONE, confidence=1.0, reasoning="Empty context", plugin_name=self.name)

        # 1. Structural Analysis
        structural_risk = self._structural_analysis(prompt)
        if structural_risk:
            return structural_risk

        # 2. Obfuscation & Entropy Analysis
        if self._detect_obfuscation(prompt):
            return RiskScore(
                level=RiskLevel.HIGH,
                confidence=0.95,
                reasoning="Obfuscated content detected (Base64/Hex encoding). Potential evasion attempt.",
                plugin_name=self.name
            )
            
        entropy = self._calculate_entropy(prompt)
        if entropy > 5.5: # Threshold for standard English text is usually lower
            return RiskScore(
                level=RiskLevel.MEDIUM,
                confidence=0.75,
                reasoning=f"High entropy content detected ({entropy:.2f}). May contain encrypted payloads.",
                plugin_name=self.name
            )

        # 3. Future LLM Integration Placeholder
        # Here we would normally call an async ML model to classify the prompt

        return RiskScore(
            level=RiskLevel.NONE,
            confidence=0.9,
            reasoning="Context validation passed advanced heuristics and structural checks.",
            plugin_name=self.name
        )
