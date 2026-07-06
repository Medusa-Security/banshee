from typing import List, Dict, Any, Callable
from banshee.core.types import RiskScore, RiskLevel, SecurityDecision, SecurityAction

class DeclarativePolicyEngine:
    """
    Evaluates a set of declarative rules to aggregate risk scores into a SecurityDecision.
    """
    def __init__(self, rules: List[Dict[str, Any]] = None):
        """
        rules parameter should be a list of dicts, e.g.:
        [
            {"condition": lambda scores: any(s.level == RiskLevel.CRITICAL for s in scores), "action": SecurityAction.DENY},
            {"condition": lambda scores: any(s.level == RiskLevel.HIGH for s in scores), "action": SecurityAction.QUARANTINE},
        ]
        If no rules match, a default action is taken.
        """
        self.rules = rules or self._default_rules()

    def _default_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "Block Critical",
                "condition": lambda scores: any(s.level == RiskLevel.CRITICAL for s in scores),
                "action": SecurityAction.DENY
            },
            {
                "name": "Quarantine High",
                "condition": lambda scores: any(s.level == RiskLevel.HIGH for s in scores),
                "action": SecurityAction.QUARANTINE
            },
            {
                "name": "Review Medium",
                "condition": lambda scores: any(s.level == RiskLevel.MEDIUM for s in scores),
                "action": SecurityAction.REQUIRES_HUMAN
            }
        ]

    def evaluate(self, scores: List[RiskScore]) -> SecurityDecision:
        if not scores:
            return SecurityDecision(
                action=SecurityAction.ALLOW,
                aggregate_risk=RiskLevel.NONE,
                aggregate_confidence=1.0,
                reasons=["No security plugins evaluated this event."]
            )

        highest_risk = RiskLevel.NONE
        reasons = []
        total_confidence = 0.0

        for score in scores:
            if score.level > highest_risk:
                highest_risk = score.level
            reasons.append(f"[{score.plugin_name}]: {score.reasoning} (Risk: {score.level.value}, Confidence: {score.confidence})")
            total_confidence += score.confidence

        avg_confidence = total_confidence / len(scores)
        action = SecurityAction.ALLOW # Default fallback

        for rule in self.rules:
            try:
                if rule["condition"](scores):
                    action = rule["action"]
                    reasons.append(f"Policy Rule Matched: {rule.get('name', 'Unnamed Rule')}")
                    break # Stop at first matched rule
            except Exception as e:
                reasons.append(f"Rule Evaluation Error: {str(e)}")

        return SecurityDecision(
            action=action,
            aggregate_risk=highest_risk,
            aggregate_confidence=avg_confidence,
            reasons=reasons
        )
