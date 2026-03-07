"""Tests for the base adapter and circuit breaker."""

from __future__ import annotations

import pytest

from src.integrations.base_adapter import CircuitBreaker, CircuitState


class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold_failures(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_failure_count(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()  # Only 1 failure after reset
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_cooldown(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

        # With 0 cooldown, should immediately go to half-open
        assert cb.allow_request() is True
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_success_closes(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=0)
        cb.record_failure()
        cb.allow_request()  # Moves to half-open
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_stays_open_during_cooldown(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, cooldown_seconds=9999)
        cb.record_failure()
        assert cb.allow_request() is False
