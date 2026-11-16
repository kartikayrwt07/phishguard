"""
URLhaus Threat Intelligence Provider Adapter.
Queries the abuse.ch URLhaus API for verified malware and phishing distributions.
"""
import time
from typing import Any, Dict, Optional

from app.intelligence.base import ProviderResult, ThreatProvider
from app.intelligence.ssrf_client import SSRFProtectionError, SSRFSafeClient


class URLhausProvider(ThreatProvider):
    """
    Adapter for the abuse.ch URLhaus API.
    Provides verified intelligence on malicious URLs and domains.
    """

    def __init__(
        self,
        base_url: str = "https://urlhaus-api.abuse.ch/v1",
        is_enabled: bool = True,
        timeout_seconds: float = 2.0,
        api_key: Optional[str] = None,
        ssrf_client: Optional[SSRFSafeClient] = None,
    ):
        super().__init__(
            name="urlhaus",
            is_enabled=is_enabled,
            timeout_seconds=timeout_seconds,
            ssrf_client=ssrf_client,
        )
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    async def lookup_url(self, url: str) -> ProviderResult:
        """Query URLhaus for a specific URL."""
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
        endpoint = f"{self.base_url}/url/"
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            response = await self.ssrf_client.post(
                endpoint,
                headers=headers,
                data={"url": url},
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
            query_status = data.get("query_status")

            if query_status == "ok":
                self.circuit_breaker.record_success()
                url_status = data.get("url_status", "unknown")
                threat = data.get("threat", "malicious_url")
                ref = data.get("urlhaus_reference")
                tags = data.get("tags") or []

                return ProviderResult(
                    provider_name=self.name,
                    is_threat=True,
                    threat_type="phishing" if "phishing" in tags else threat,
                    severity="critical" if url_status == "online" else "high",
                    confidence=0.95,
                    reference_url=ref,
                    query_time_ms=elapsed_ms,
                    details={
                        "url_status": url_status,
                        "tags": tags,
                        "date_added": data.get("date_added"),
                        "reporter": data.get("reporter"),
                    },
                )
            elif query_status == "no_results":
                self.circuit_breaker.record_success()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    confidence=0.0,
                    query_time_ms=elapsed_ms,
                    details={"query_status": "no_results"},
                )
            else:
                # API error or unexpected query status
                self.circuit_breaker.record_failure()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    query_time_ms=elapsed_ms,
                    error=f"URLhaus unexpected query_status: {query_status}",
                    details=data,
                )

        except SSRFProtectionError as e:
            # SSRF block is an intentional policy reject, not a circuit failure
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
        """Query URLhaus for a domain or hostname."""
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
        endpoint = f"{self.base_url}/host/"
        headers = {}
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        try:
            response = await self.ssrf_client.post(
                endpoint,
                headers=headers,
                data={"host": domain},
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
            query_status = data.get("query_status")

            if query_status == "ok":
                self.circuit_breaker.record_success()
                urls = data.get("urls") or []
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=len(urls) > 0,
                    threat_type="phishing" if any("phishing" in (u.get("tags") or []) for u in urls) else "malware",
                    severity="high",
                    confidence=0.90 if urls else 0.0,
                    reference_url=data.get("urlhaus_reference"),
                    query_time_ms=elapsed_ms,
                    details={"active_threat_count": len(urls), "firstseen": data.get("firstseen")},
                )
            elif query_status == "no_results":
                self.circuit_breaker.record_success()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    confidence=0.0,
                    query_time_ms=elapsed_ms,
                    details={"query_status": "no_results"},
                )
            else:
                self.circuit_breaker.record_failure()
                return ProviderResult(
                    provider_name=self.name,
                    is_threat=False,
                    query_time_ms=elapsed_ms,
                    error=f"URLhaus unexpected query_status: {query_status}",
                    details=data,
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
