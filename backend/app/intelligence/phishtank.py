"""
PhishTank Threat Intelligence Provider Adapter.
Queries the PhishTank API for community-verified phishing sites.
"""
import time
from typing import Any, Dict, Optional

from app.intelligence.base import ProviderResult, ThreatProvider
from app.intelligence.ssrf_client import SSRFProtectionError, SSRFSafeClient


class PhishTankProvider(ThreatProvider):
    """
    Adapter for the PhishTank API.
    Provides community-verified phishing threat intelligence.
    """

    def __init__(
        self,
        endpoint_url: str = "https://checkurl.phishtank.com/checkurl/",
        api_key: Optional[str] = None,
        app_name: str = "PhishGuard",
        is_enabled: bool = True,
        timeout_seconds: float = 2.0,
        ssrf_client: Optional[SSRFSafeClient] = None,
    ):
        super().__init__(
            name="phishtank",
            is_enabled=is_enabled,
            timeout_seconds=timeout_seconds,
            ssrf_client=ssrf_client,
        )
        self.endpoint_url = endpoint_url
        self.api_key = api_key
        self.app_name = app_name

    async def lookup_url(self, url: str) -> ProviderResult:
        """Query PhishTank for a specific URL."""
        if not self.is_enabled:
            return ProviderResult(
                provider_name=self.name,
                is_threat=False,
                error="Provider is disabled",
            )

        if not self.circuit_breaker.allow_request():
            return ProviderResult(
                provider_name=self.name,
                is_threat=False,
                error="Circuit breaker is OPEN",
            )

        start_time = time.monotonic()
        payload: Dict[str, Any] = {
            "url": url,
            "format": "json",
        }
        if self.api_key:
            payload["app_key"] = self.api_key

        headers = {
            "User-Agent": f"phishtank/{self.app_name}",
        }

        try:
            response = await self.ssrf_client.post(
                self.endpoint_url,
                headers=headers,
                data=payload,
            )
            elapsed_ms = (time.monotonic() - start_time) * 1000.0

            if response.status_code != 200:
                self.circuit_breaker.record_failure()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    query_time_ms=elapsed_ms,
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                )

            data = response.json()
            results = data.get("results", {})
            in_database = results.get("in_database", False)

            if in_database:
                self.circuit_breaker.record_success()
                verified = results.get("verified", False)
                valid = results.get("valid", False)
                phish_id = results.get("phish_id")
                detail_url = results.get("phish_detail_page")

                is_active_phish = valid and (verified or not valid)
                confidence = 0.98 if verified else 0.85

                return ProviderResult(
                    provider_name=self.name,
                    is_threat=is_active_phish,
                    threat_type="phishing",
                    severity="critical" if verified else "high",
                    confidence=confidence if is_active_phish else 0.0,
                    reference_url=detail_url,
                    query_time_ms=elapsed_ms,
                    details={
                        "phish_id": phish_id,
                        "verified": verified,
                        "valid": valid,
                        "verified_at": results.get("verified_at"),
                    },
                )
            else:
                self.circuit_breaker.record_success()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    confidence=0.0,
                    query_time_ms=elapsed_ms,
                    details={"in_database": False},
                )

        except SSRFProtectionError as e:
            elapsed_ms = (time.monotonic() - start_time) * 1000.0
            return ProviderResult(
                provider_name=self.name,
                is_threat=False,
                query_time_ms=elapsed_ms,
                error=f"SSRF blocked: {e}",
            )
        except Exception as e:
            self.circuit_breaker.record_failure()
            elapsed_ms = (time.monotonic() - start_time) * 1000.0
            return ProviderResult(
                provider_name=self.name,
                is_threat=False,
                query_time_ms=elapsed_ms,
                error=f"Network or parsing error: {e}",
            )

    async def lookup_domain(self, domain: str) -> ProviderResult:
        """
        PhishTank API is URL-centric; query the root domain URL.
        """
        probe_url = f"http://{domain}/"
        return await self.lookup_url(probe_url)
