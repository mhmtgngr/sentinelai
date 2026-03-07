"""Abstract base class for all Sentinel-AI agents.

Each agent processes security events and produces AgentDecision objects.
See docs/agent-coordination.md for lifecycle and coordination details.
"""

from __future__ import annotations

import abc
import asyncio
import logging
from datetime import datetime

from src.core.models import AgentDecision, Alert

logger = logging.getLogger(__name__)


class BaseAgent(abc.ABC):
    """Abstract base for all security agents.

    Subclasses must implement:
        - process(): Core logic for processing an alert
        - capabilities: Property listing what this agent can do
    """

    def __init__(
        self,
        agent_id: str,
        timeout_seconds: float = 60.0,
        confidence_threshold: float = 0.75,
        max_retries: int = 3,
    ) -> None:
        self.agent_id = agent_id
        self.timeout_seconds = timeout_seconds
        self.confidence_threshold = confidence_threshold
        self.max_retries = max_retries
        self._is_processing = False

    @property
    @abc.abstractmethod
    def capabilities(self) -> list[str]:
        """List of capabilities this agent provides (e.g., 'triage', 'hunt', 'respond')."""
        ...

    @abc.abstractmethod
    async def process(self, alert: Alert) -> AgentDecision:
        """Process an alert and return a decision.

        This is the core logic method. Implementations should:
        1. Analyze the alert data
        2. Consult relevant data sources
        3. Produce a decision with confidence score and reasoning trace
        """
        ...

    async def execute(self, alert: Alert) -> AgentDecision:
        """Execute agent processing with timeout and error handling.

        This wraps process() with:
        - Timeout enforcement
        - Error logging
        - State tracking
        """
        self._is_processing = True
        try:
            decision = await asyncio.wait_for(
                self.process(alert),
                timeout=self.timeout_seconds,
            )
            logger.info(
                "Agent '%s' processed alert '%s' (confidence: %.2f)",
                self.agent_id,
                alert.id,
                decision.confidence,
            )
            return decision
        except asyncio.TimeoutError:
            logger.error(
                "Agent '%s' timed out after %.0fs on alert '%s'",
                self.agent_id,
                self.timeout_seconds,
                alert.id,
            )
            return AgentDecision(
                agent_id=self.agent_id,
                alert_id=alert.id,
                confidence=0.0,
                reasoning_trace=[f"Agent timed out after {self.timeout_seconds}s"],
                timestamp=datetime.utcnow(),
            )
        except Exception:
            logger.exception("Agent '%s' failed on alert '%s'", self.agent_id, alert.id)
            return AgentDecision(
                agent_id=self.agent_id,
                alert_id=alert.id,
                confidence=0.0,
                reasoning_trace=["Agent encountered an unrecoverable error"],
                timestamp=datetime.utcnow(),
            )
        finally:
            self._is_processing = False

    @property
    def is_processing(self) -> bool:
        """Whether this agent is currently processing a task."""
        return self._is_processing

    def meets_confidence_threshold(self, decision: AgentDecision) -> bool:
        """Check if a decision meets this agent's confidence threshold."""
        return decision.confidence >= self.confidence_threshold
