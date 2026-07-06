from typing import List, Optional
from banshee.plugins.base import BansheePlugin
from banshee.core.events import SecurityEvent, EventCategory
from banshee.core.types import RiskScore, RiskLevel
from banshee.intelligence.llm import LLMProvider

class IntelligenceSecurityPlugin(BansheePlugin):
    """
    Leverages an external LLM provider to evaluate complex security contexts
    that static heuristics might miss (e.g., sophisticated prompt injections,
    jailbreaks, or highly contextual execution risks).
    """
    def __init__(self, provider: LLMProvider):
        self.provider = provider
        super().__init__()

    @property
    def name(self) -> str:
        return f"IntelligenceEvaluator({self.provider.__class__.__name__})"

    @property
    def supported_categories(self) -> List[EventCategory]:
        return [EventCategory.CONTEXT, EventCategory.EXECUTION, EventCategory.PATCH]

    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        prompt = event.payload.get("prompt", "")
        if not prompt and event.category == EventCategory.EXECUTION:
            prompt = event.payload.get("command", "")
        if not prompt and event.category == EventCategory.PATCH:
            prompt = event.payload.get("diff", "")
            
        if not prompt:
            return RiskScore(
                level=RiskLevel.NONE,
                confidence=1.0,
                reasoning="No text payload to evaluate.",
                plugin_name=self.name
            )

        context = f"Event Category: {event.category.name if hasattr(event.category, 'name') else event.category}\nAction: {event.action}"
        
        # Evaluate using the provided LLM
        result = await self.provider.evaluate_security_risk(prompt, context)
        
        risk_str = result.get("risk_level", "medium").upper()
        
        try:
            risk_level = RiskLevel[risk_str]
        except KeyError:
            risk_level = RiskLevel.MEDIUM
            
        return RiskScore(
            level=risk_level,
            confidence=result.get("confidence", 0.5),
            reasoning=result.get("reasoning", "LLM Evaluation completed."),
            plugin_name=self.name
        )
