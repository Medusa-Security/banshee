import abc
import asyncio
from typing import List, Optional
from banshee.core.events import SecurityEvent
from banshee.core.types import RiskScore, RiskLevel

class BansheePlugin(abc.ABC):
    """
    Abstract base class for all Banshee security plugins.
    Supports asynchronous execution with configurable timeouts.
    """
    
    timeout_seconds: float = 5.0  # Default timeout for plugin execution

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the plugin."""
        pass

    @property
    @abc.abstractmethod
    def supported_categories(self) -> List[str]:
        """List of EventCategories this plugin can process."""
        pass

    @abc.abstractmethod
    async def analyze_event(self, event: SecurityEvent) -> RiskScore:
        """
        Analyze a security event and return a risk score.
        """
        pass

    async def execute_with_timeout(self, event: SecurityEvent) -> RiskScore:
        """
        Execute the analysis with a strict timeout.
        """
        try:
            return await asyncio.wait_for(self.analyze_event(event), timeout=self.timeout_seconds)
        except asyncio.TimeoutError:
            return self.fallback_score(event, "Plugin execution timed out.")
        except Exception as e:
            return self.fallback_score(event, f"Plugin execution failed: {str(e)}")

    def fallback_score(self, event: SecurityEvent, reason: str) -> RiskScore:
        """
        Fallback score if the plugin fails or times out.
        Subclasses can override this for safer defaults (e.g., fail-closed).
        """
        return RiskScore(
            level=RiskLevel.MEDIUM, # Default to medium risk on failure
            confidence=0.0,
            reasoning=f"FALLBACK: {reason}",
            plugin_name=self.name
        )

    async def initialize(self) -> None:
        """Optional initialization logic for the plugin."""
        pass

    async def teardown(self) -> None:
        """Optional teardown logic for the plugin."""
        pass
