"""
Base interfaces, circuit breaker, and data structures for external Threat Intelligence providers.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import time
from typing import Any, Dict, Optional

from app.intelligence.ssrf_client import SSRFSafeClient


class CircuitState(str, Enum):
    CLOSED = "closed"        # Normal operation: all queries allowed
    OPEN = "open"            # Tripped: fail fast without making external network calls
    HALF_OPEN = "half_open"  # Cooldown expired: probe request in flight to test recovery


class CircuitBreakerOpenError(Exception):
    """Raised when an operation is attempted while the circuit breaker is OPEN."""
    pass


class CircuitBreaker:
    """
    In-memory Circuit Breaker to prevent cascading failures and protect
    detection latency when external threat feeds experience outages.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
    ):
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.last_failure_time: Optional[float] = None
        self.last_state_change: float = time.monotonic()
        self.total_queries = 0
        self.total_failures = 0
        self.total_trips = 0

    def allow_request(self) -> bool:
        """
        Check if a request is permitted under the current circuit state.
        """
        now = time.monotonic()

        if self.state == CircuitState.CLOSED:
            return True

        if self.state == CircuitState.OPEN:
            # Check if cooldown has elapsed
            if self.last_failure_time is not None and (now - self.last_failure_time) >= self.cooldown_seconds:
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = now
                return True
            return False

        if self.state == CircuitState.HALF_OPEN:
            # Allow a probe request through
            return True

        return False

    def record_success(self) -> None:
        """Record a successful provider request."""
        self.total_queries += 1
        self.consecutive_failures = 0

        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.last_state_change = time.monotonic()

    def record_failure(self) -> None:
        """Record a failed provider request (timeout, network error, 5xx)."""
        self.total_queries += 1
        self.total_failures += 1
        self.consecutive_failures += 1
        now = time.monotonic()
        self.last_failure_time = now

        if self.state == CircuitState.HALF_OPEN:
            # Probe failed, reopen immediately
            self.state = CircuitState.OPEN
            self.last_state_change = now
            self.total_trips += 1
        elif self.state == CircuitState.CLOSED:
            if self.consecutive_failures >= self.failure_threshold:
                self.state = CircuitState.OPEN
                self.last_state_change = now
                self.total_trips += 1

    def reset(self) -> None:
        """Manually reset the circuit breaker to CLOSED."""
        self.state = CircuitState.CLOSED
        self.consecutive_failures = 0
        self.last_failure_time = None
        self.last_state_change = time.monotonic()


@dataclass(frozen=True)
class ProviderResult:
    """Standardized result returned by all threat intelligence provider adapters."""
    provider_name: str
    is_threat: bool
    threat_type: Optional[str] = None          # e.g. "phishing", "malware"
    severity: Optional[str] = None             # "critical", "high", "medium", "low"
    confidence: float = 0.0                    # 0.0 to 1.0
    reference_url: Optional[str] = None
    query_time_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider_name": self.provider_name,
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "reference_url": self.reference_url,
            "query_time_ms": self.query_time_ms,
            "details": self.details,
            "error": self.error,
        }


@dataclass(frozen=True)
class ProviderHealth:
    """Health and status metrics for an external provider adapter."""
    provider_name: str
    is_enabled: bool
    circuit_state: CircuitState
    consecutive_failures: int
    total_queries: int
    total_failures: int
    total_trips: int
    last_state_change_utc: str


class ThreatProvider(ABC):
    """
    Abstract base class for all threat intelligence providers.
    Enforces isolation, circuit breaking, timeouts, and SSRF protection.
    """

    def __init__(
        self,
        name: str,
        is_enabled: bool = True,
        timeout_seconds: float = 2.0,
        failure_threshold: int = 5,
        cooldown_seconds: float = 30.0,
        ssrf_client: Optional[SSRFSafeClient] = None,
    ):
        self.name = name
        self.is_enabled = is_enabled
        self.timeout_seconds = timeout_seconds
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self.ssrf_client = ssrf_client or SSRFSafeClient(timeout_seconds=timeout_seconds)

    def get_health(self) -> ProviderHealth:
        """Inspect provider circuit breaker state and query counters."""
        return ProviderHealth(
            provider_name=self.name,
            is_enabled=self.is_enabled,
            circuit_state=self.circuit_breaker.state,
            consecutive_failures=self.circuit_breaker.consecutive_failures,
            total_queries=self.circuit_breaker.total_queries,
            total_failures=self.circuit_breaker.total_failures,
            total_trips=self.circuit_breaker.total_trips,
            last_state_change_utc=datetime.now(timezone.utc).isoformat(),
        )

    @abstractmethod
    async def lookup_url(self, url: str) -> ProviderResult:
        """Query provider for reputation of a full URL."""
        pass

    @abstractmethod
    async def lookup_domain(self, domain: str) -> ProviderResult:
        """Query provider for reputation of a domain name."""
        pass

