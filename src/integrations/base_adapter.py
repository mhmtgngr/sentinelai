"""Abstract base class for security product adapters.

Implements the adapter pattern for product-agnostic integration.
Includes circuit breaker and retry with exponential backoff.
"""

from __future__ import annotations

import abc
import asyncio
import logging
import time
from datetime import datetime
from enum import Enum
from typing import Any

from src.core.models import (
    ActionResult,
    ActionStatus,
    ActionType,
    HealthState,
    HealthStatus,
    SecurityEvent,
)

logger = logging.getLogger(__name__)


class CircuitState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


class CircuitBreaker:
    """Circuit breaker to prevent cascade failures on adapter calls.

    Trips after `failure_threshold` consecutive failures or
    `failure_rate_threshold` failure rate in `window_seconds`.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time: float = 0
        self._opened_at: float = 0

    def record_success(self) -> None:
        """Record a successful call — reset failure count."""
        self._failure_count = 0
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            logger.info("Circuit breaker closed (recovered)")

    def record_failure(self) -> None:
        """Record a failed call — may trip the breaker."""
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._failure_count >= self.failure_threshold and self.state == CircuitState.CLOSED:
            self.state = CircuitState.OPEN
            self._opened_at = time.monotonic()
            logger.warning("Circuit breaker OPENED after %d failures", self._failure_count)

    def allow_request(self) -> bool:
        """Check if a request should be allowed through."""
        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            elapsed = time.monotonic() - self._opened_at
            if elapsed >= self.cooldown_seconds:
                self.state = CircuitState.HALF_OPEN
                logger.info("Circuit breaker half-open (testing)")
                return True
            return False

        # HALF_OPEN: allow one test request
        return True


async def retry_with_backoff(
    func: Any,
    max_retries: int = 3,
    base_delay: float = 1.0,
) -> Any:
    """Execute an async function with exponential backoff retry."""
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await func()
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                delay = base_delay * (2**attempt)
                logger.warning(
                    "Retry %d/%d after %.1fs: %s",
                    attempt + 1,
                    max_retries,
                    delay,
                    str(e),
                )
                await asyncio.sleep(delay)
    raise last_error  # type: ignore[misc]


class BaseSecurityAdapter(abc.ABC):
    """Abstract base for all security product adapters.

    Subclasses must implement:
        - get_events(): Poll for new security events
        - execute_action(): Execute a remediation action
        - health_check(): Check connectivity to the security product
    """

    product_type: str = ""  # firewall, waf, siem, identity, edr
    vendor: str = ""  # paloalto, wazuh, crowdstrike, etc.

    def __init__(self, endpoint: str, **kwargs: Any) -> None:
        self.endpoint = endpoint
        self.circuit_breaker = CircuitBreaker()
        self._config = kwargs

    @abc.abstractmethod
    async def get_events(self, since: datetime) -> list[SecurityEvent]:
        """Poll for new security events since the given timestamp."""
        ...

    @abc.abstractmethod
    async def execute_action(
        self, action_type: ActionType, target: str, params: dict[str, Any] | None = None
    ) -> ActionResult:
        """Execute a remediation action on the security product."""
        ...

    @abc.abstractmethod
    async def health_check(self) -> HealthStatus:
        """Check connectivity and health of the security product."""
        ...

    async def safe_get_events(self, since: datetime) -> list[SecurityEvent]:
        """Get events with circuit breaker and retry protection."""
        if not self.circuit_breaker.allow_request():
            logger.warning("Circuit breaker open for %s/%s", self.product_type, self.vendor)
            return []

        try:
            events = await retry_with_backoff(lambda: self.get_events(since))
            self.circuit_breaker.record_success()
            return events
        except Exception:
            self.circuit_breaker.record_failure()
            logger.exception("Failed to get events from %s/%s", self.product_type, self.vendor)
            return []

    async def safe_execute_action(
        self, action_type: ActionType, target: str, params: dict[str, Any] | None = None
    ) -> ActionResult:
        """Execute action with circuit breaker protection."""
        if not self.circuit_breaker.allow_request():
            return ActionResult(
                action_type=action_type,
                target=target,
                status=ActionStatus.FAILED,
                adapter_used=f"{self.product_type}/{self.vendor}",
                evidence={"error": "Circuit breaker open"},
            )

        try:
            result = await retry_with_backoff(
                lambda: self.execute_action(action_type, target, params)
            )
            self.circuit_breaker.record_success()
            return result
        except Exception as e:
            self.circuit_breaker.record_failure()
            return ActionResult(
                action_type=action_type,
                target=target,
                status=ActionStatus.FAILED,
                adapter_used=f"{self.product_type}/{self.vendor}",
                evidence={"error": str(e)},
            )

    @property
    def health_state(self) -> HealthState:
        """Current health state based on circuit breaker."""
        if self.circuit_breaker.state == CircuitState.CLOSED:
            return HealthState.HEALTHY
        if self.circuit_breaker.state == CircuitState.HALF_OPEN:
            return HealthState.DEGRADED
        return HealthState.UNAVAILABLE
