"""
Threat Intelligence module for PhishGuard.
Provides SSRF-safe network transport, isolated threat feed adapters, circuit breaking, and orchestration.
"""
from app.intelligence.base import (
    CircuitBreaker,
    CircuitBreakerOpenError,
    CircuitState,
    ProviderHealth,
    ProviderResult,
    ThreatProvider,
)
from app.intelligence.phishtank import PhishTankProvider
from app.intelligence.service import ThreatEnrichmentResult, ThreatIntelligenceService
from app.intelligence.ssrf_client import (
    PROHIBITED_NETWORKS,
    SSRFProtectionError,
    SSRFSafeClient,
    is_ip_prohibited,
    resolve_and_validate_host,
)
from app.intelligence.urlhaus import URLhausProvider

__all__ = [
    "CircuitBreaker",
    "CircuitBreakerOpenError",
    "CircuitState",
    "ProviderHealth",
    "ProviderResult",
    "ThreatProvider",
    "URLhausProvider",
    "PhishTankProvider",
    "ThreatIntelligenceService",
    "ThreatEnrichmentResult",
    "SSRFSafeClient",
    "SSRFProtectionError",
    "PROHIBITED_NETWORKS",
    "is_ip_prohibited",
    "resolve_and_validate_host",
]
