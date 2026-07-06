import asyncio
import logging
from typing import List
from banshee.core.events import SecurityEvent
from banshee.core.types import RiskScore
from banshee.plugins.base import BansheePlugin

logger = logging.getLogger(__name__)

class EventBroker:
    """
    Asynchronous Microkernel event broker.
    Routes security events to the appropriate plugins, handles enrichment, and manages timeouts.
    """
    def __init__(self):
        self._plugins: List[BansheePlugin] = []

    def register_plugin(self, plugin: BansheePlugin) -> None:
        self._plugins.append(plugin)
        logger.info(f"Registered plugin: {plugin.name}")

    async def enrich_event(self, event: SecurityEvent) -> SecurityEvent:
        """
        Enrich the event with additional context before dispatching.
        Currently a placeholder for future complex enrichment (e.g., DB lookups).
        """
        if not hasattr(event, "enriched_metadata"):
            event.payload["enriched"] = True
        return event

    async def dispatch(self, event: SecurityEvent) -> List[RiskScore]:
        """
        Dispatch the enriched event to all relevant plugins concurrently.
        """
        enriched_event = await self.enrich_event(event)

        relevant_plugins = [
            p for p in self._plugins 
            if enriched_event.category.value in [c.value if hasattr(c, 'value') else c for c in p.supported_categories]
        ]

        if not relevant_plugins:
            logger.debug(f"No plugins registered for event category: {enriched_event.category}")
            return []

        # Run all relevant plugins concurrently with individual timeouts handled inside the plugin base
        tasks = [plugin.execute_with_timeout(enriched_event) for plugin in relevant_plugins]
        scores = await asyncio.gather(*tasks)
        
        return list(scores)
