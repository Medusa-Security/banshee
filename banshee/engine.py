from banshee.core.bus import EventBroker
from banshee.core.policy import DeclarativePolicyEngine
from banshee.core.audit import AuditTrail
from banshee.core.events import SecurityEvent
from banshee.core.types import SecurityDecision
from banshee.plugins.base import BansheePlugin

class BansheeEngine:
    """
    The main orchestrator for Banshee security operations.
    Utilizes an Asynchronous Microkernel (EventBroker) and a Declarative Policy Engine.
    """
    def __init__(self, audit_log_path: str = "banshee_audit.jsonl", policy_rules=None):
        self.broker = EventBroker()
        self.policy = DeclarativePolicyEngine(rules=policy_rules)
        self.audit = AuditTrail(audit_log_path)
        
    async def evaluate_event(self, event: SecurityEvent) -> SecurityDecision:
        """
        Intercept an event, evaluate it via the async broker, apply policy, and audit.
        """
        scores = await self.broker.dispatch(event)
        decision = self.policy.evaluate(scores)
        self.audit.record(event, decision)
        return decision
        
    def register_plugin(self, plugin: BansheePlugin) -> None:
        """
        Register a security plugin with the engine's event broker.
        """
        self.broker.register_plugin(plugin)

    def load_default_plugins(self) -> None:
        """
        Load all default advanced plugins for a fully operational security engine.
        """
        from banshee.plugins.context import ContextValidationPlugin
        from banshee.plugins.execution import ExecutionSecurityPlugin
        from banshee.plugins.patch import AdvancedPatchSecurityPlugin
        from banshee.plugins.knowledge import KnowledgeVerificationPlugin
        from banshee.plugins.memory import AdvancedMemorySecurityPlugin
        from banshee.plugins.behavioral import BehavioralSecurityPlugin
        from banshee.plugins.network import NetworkSecurityPlugin
        from banshee.plugins.dlp import DataLossPreventionPlugin

        self.register_plugin(ContextValidationPlugin())
        self.register_plugin(ExecutionSecurityPlugin())
        self.register_plugin(AdvancedPatchSecurityPlugin())
        self.register_plugin(KnowledgeVerificationPlugin())
        self.register_plugin(AdvancedMemorySecurityPlugin())
        self.register_plugin(BehavioralSecurityPlugin())
        self.register_plugin(NetworkSecurityPlugin())
        self.register_plugin(DataLossPreventionPlugin())


