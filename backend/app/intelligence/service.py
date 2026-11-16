"""
Threat Intelligence Service.
Coordinates parallel queries across external threat feeds, enforcing timeouts,
circuit breaking, and aggregating threat intelligence indicators for the detection engine.
"""
import asyncio
from dataclasses import dataclass, field
import time
from typing import Any, Dict, List, Optional

from app.intelligence.base import ProviderHealth, ProviderResult, ThreatProvider
from app.intelligence.phishtank import PhishTankProvider
from app.intelligence.urlhaus import URLhausProvider


@dataclass(frozen=True)
class ThreatEnrichmentResult:
    """Aggregated threat intelligence lookup result across all active providers."""
    query_target: str
    is_threat: bool
    threat_type: Optional[str] = None
    highest_severity: Optional[str] = None
    highest_confidence: float = 0.0
    confirmed_sources: List[str] = field(default_factory=list)
    provider_results: Dict[str, ProviderResult] = field(default_factory=dict)
    total_query_time_ms: float = 0.0
    evidence_summary: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_target": self.query_target,
            "is_threat": self.is_threat,
            "threat_type": self.threat_type,
            "highest_severity": self.highest_severity,
            "highest_confidence": self.highest_confidence,
            "confirmed_sources": self.confirmed_sources,
            "provider_results": {k: v.to_dict() for k, v in self.provider_results.items()},
            "total_query_time_ms": self.total_query_time_ms,
            "evidence_summary": self.evidence_summary,
        }


class ThreatIntelligenceService:
    """
    Central service orchestrating external threat intelligence lookups.
    Queries registered providers in parallel with timeout budgets and circuit breaking.
    """

    def __init__(self, providers: Optional[List[ThreatProvider]] = None):
        self.providers: Dict[str, ThreatProvider] = {}
        if providers:
            for p in providers:
                self.register_provider(p)
        else:
            # Register default providers
            self.register_provider(URLhausProvider())
            self.register_provider(PhishTankProvider())

    def register_provider(self, provider: ThreatProvider) -> None:
        """Register or replace a threat intelligence provider."""
        self.providers[provider.name] = provider

    def get_provider(self, name: str) -> Optional[ThreatProvider]:
        """Retrieve a registered provider by name."""
        return self.providers.get(name)

    def get_health_all(self) -> Dict[str, ProviderHealth]:
        """Get circuit breaker and health metrics for all registered providers."""
        return {name: provider.get_health() for name, provider in self.providers.items()}

    async def check_url(
        self,
        url: str,
        timeout_budget_seconds: float = 2.5,
    ) -> ThreatEnrichmentResult:
        """
        Query all enabled providers concurrently for a URL within the allotted timeout budget.
        """
        start_time = time.monotonic()
        enabled_providers = [p for p in self.providers.values() if p.is_enabled]

        if not enabled_providers:
            return ThreatEnrichmentResult(
                query_target=url,
                is_threat=False,
                total_query_time_ms=0.0,
            )

        # Launch concurrent lookups
        async def _query(p: ThreatProvider) -> ProviderResult:
            try:
                return await p.lookup_url(url)
            except Exception as e:
                p.circuit_breaker.record_failure()
                return ProviderResult(
                    provider_name=p.name,
                    is_threat=False,
                    error=f"Unhandled exception in provider: {e}",
                )

        tasks = [_query(p) for p in enabled_providers]

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout_budget_seconds,
            )
        except asyncio.TimeoutError:
            # Timeout budget exceeded for the batch
            results = [
                ProviderResult(
                    provider_name=p.name,
                    is_threat=False,
                    error=f"Query timed out exceeding overall budget of {timeout_budget_seconds}s",
                )
                for p in enabled_providers
            ]

        total_elapsed_ms = (time.monotonic() - start_time) * 1000.0

        provider_results_dict: Dict[str, ProviderResult] = {}
        confirmed_sources: List[str] = []
        is_threat = False
        highest_confidence = 0.0
        highest_severity: Optional[str] = None
        detected_threat_type: Optional[str] = None
        evidence_descriptions: List[str] = []

        # Severity ranking for comparison
        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for idx, res in enumerate(results):
            provider = enabled_providers[idx]
            if isinstance(res, Exception):
                provider_res = ProviderResult(
                    provider_name=provider.name,
                    is_threat=False,
                    error=f"Task exception: {res}",
                )
            else:
                provider_res = res

            provider_results_dict[provider.name] = provider_res

            if provider_res.is_threat:
                is_threat = True
                confirmed_sources.append(provider.name)
                if provider_res.confidence > highest_confidence:
                    highest_confidence = provider_res.confidence

                current_rank = severity_rank.get(highest_severity or "low", 0)
                new_rank = severity_rank.get(provider_res.severity or "high", 3)
                if new_rank >= current_rank:
                    highest_severity = provider_res.severity or "high"

                if not detected_threat_type or provider_res.threat_type == "phishing":
                    detected_threat_type = provider_res.threat_type or "phishing"

                evidence_descriptions.append(
                    f"{provider.name}: Confirmed {provider_res.threat_type or 'threat'} (severity: {provider_res.severity}, confidence: {provider_res.confidence:.2f})"
                )

        evidence_summary = "; ".join(evidence_descriptions) if evidence_descriptions else None

        return ThreatEnrichmentResult(
            query_target=url,
            is_threat=is_threat,
            threat_type=detected_threat_type,
            highest_severity=highest_severity,
            highest_confidence=highest_confidence,
            confirmed_sources=confirmed_sources,
            provider_results=provider_results_dict,
            total_query_time_ms=total_elapsed_ms,
            evidence_summary=evidence_summary,
        )

    async def check_domain(
        self,
        domain: str,
        timeout_budget_seconds: float = 2.5,
    ) -> ThreatEnrichmentResult:
        """
        Query all enabled providers concurrently for a domain name.
        """
        start_time = time.monotonic()
        enabled_providers = [p for p in self.providers.values() if p.is_enabled]

        if not enabled_providers:
            return ThreatEnrichmentResult(
                query_target=domain,
                is_threat=False,
                total_query_time_ms=0.0,
            )

        async def _query(p: ThreatProvider) -> ProviderResult:
            try:
                return await p.lookup_domain(domain)
            except Exception as e:
                p.circuit_breaker.record_failure()
                return ProviderResult(
                    provider_name=p.name,
                    is_threat=False,
                    error=f"Unhandled exception in provider: {e}",
                )

        tasks = [_query(p) for p in enabled_providers]

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=timeout_budget_seconds,
            )
        except asyncio.TimeoutError:
            results = [
                ProviderResult(
                    provider_name=p.name,
                    is_threat=False,
                    error=f"Query timed out exceeding overall budget of {timeout_budget_seconds}s",
                )
                for p in enabled_providers
            ]

        total_elapsed_ms = (time.monotonic() - start_time) * 1000.0

        provider_results_dict: Dict[str, ProviderResult] = {}
        confirmed_sources: List[str] = []
        is_threat = False
        highest_confidence = 0.0
        highest_severity: Optional[str] = None
        detected_threat_type: Optional[str] = None
        evidence_descriptions: List[str] = []

        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for idx, res in enumerate(results):
            provider = enabled_providers[idx]
            if isinstance(res, Exception):
                provider_res = ProviderResult(
                    provider_name=provider.name,
                    is_threat=False,
                    error=f"Task exception: {res}",
                )
            else:
                provider_res = res

            provider_results_dict[provider.name] = provider_res

            if provider_res.is_threat:
                is_threat = True
                confirmed_sources.append(provider.name)
                if provider_res.confidence > highest_confidence:
                    highest_confidence = provider_res.confidence

                current_rank = severity_rank.get(highest_severity or "low", 0)
                new_rank = severity_rank.get(provider_res.severity or "high", 3)
                if new_rank >= current_rank:
                    highest_severity = provider_res.severity or "high"

                if not detected_threat_type or provider_res.threat_type == "phishing":
                    detected_threat_type = provider_res.threat_type or "phishing"

                evidence_descriptions.append(
                    f"{provider.name}: Confirmed {provider_res.threat_type or 'threat'} (severity: {provider_res.severity}, confidence: {provider_res.confidence:.2f})"
                )

        evidence_summary = "; ".join(evidence_descriptions) if evidence_descriptions else None

        return ThreatEnrichmentResult(
            query_target=domain,
            is_threat=is_threat,
            threat_type=detected_threat_type,
            highest_severity=highest_severity,
            highest_confidence=highest_confidence,
            confirmed_sources=confirmed_sources,
            provider_results=provider_results_dict,
            total_query_time_ms=total_elapsed_ms,
            evidence_summary=evidence_summary,
        )
