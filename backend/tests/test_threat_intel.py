"""
Comprehensive tests for SSRF-Safe HTTP Client, Threat Intelligence Providers,
Circuit Breaker, and Service Aggregation.
"""
import asyncio
import socket
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from app.intelligence.base import (
    CircuitBreaker,
    CircuitState,
    ProviderHealth,
    ProviderResult,
    ThreatProvider,
)
from app.intelligence.phishtank import PhishTankProvider
from app.intelligence.service import ThreatEnrichmentResult, ThreatIntelligenceService
from app.intelligence.ssrf_client import (
    SSRFProtectionError,
    SSRFSafeClient,
    is_ip_prohibited,
    resolve_and_validate_host,
)
from app.intelligence.urlhaus import URLhausProvider


# ---------------------------------------------------------------------------
# SSRF IP Validation Tests
# ---------------------------------------------------------------------------

def test_is_ip_prohibited():
    """Verify detection of internal, loopback, private, and cloud metadata IPs."""
    # Loopback
    assert is_ip_prohibited("127.0.0.1") is True
    assert is_ip_prohibited("127.0.1.1") is True
    assert is_ip_prohibited("::1") is True

    # RFC 1918 Private
    assert is_ip_prohibited("10.0.0.1") is True
    assert is_ip_prohibited("10.255.255.254") is True
    assert is_ip_prohibited("172.16.0.1") is True
    assert is_ip_prohibited("172.31.255.254") is True
    assert is_ip_prohibited("192.168.1.1") is True

    # Cloud Metadata & Link-Local (RFC 3927)
    assert is_ip_prohibited("169.254.169.254") is True
    assert is_ip_prohibited("169.254.1.1") is True
    assert is_ip_prohibited("fe80::1") is True

    # Carrier-grade NAT (RFC 6598)
    assert is_ip_prohibited("100.64.0.1") is True

    # Documentation / Test networks (RFC 5737)
    assert is_ip_prohibited("192.0.2.1") is True
    assert is_ip_prohibited("198.51.100.1") is True
    assert is_ip_prohibited("203.0.113.1") is True

    # Public Internet addresses (Permitted)
    assert is_ip_prohibited("8.8.8.8") is False
    assert is_ip_prohibited("1.1.1.1") is False
    assert is_ip_prohibited("93.184.216.34") is False
    assert is_ip_prohibited("2606:4700:4700::1111") is False


def test_resolve_and_validate_host_raw_ips():
    """Verify raw prohibited IPs are blocked without DNS query."""
    with pytest.raises(SSRFProtectionError, match="prohibited or private"):
        resolve_and_validate_host("127.0.0.1")

    with pytest.raises(SSRFProtectionError, match="prohibited or private"):
        resolve_and_validate_host("169.254.169.254")

    with pytest.raises(SSRFProtectionError, match="prohibited or private"):
        resolve_and_validate_host("10.0.0.5")

    # Public raw IP succeeds
    ips = resolve_and_validate_host("93.184.216.34")
    assert ips == ["93.184.216.34"]


@patch("socket.getaddrinfo")
def test_resolve_and_validate_host_dns_mock(mock_getaddrinfo):
    """Verify DNS resolution blocks hosts resolving to private IPs or dual-homed setups."""
    # Host resolving to private IP
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))
    ]
    with pytest.raises(SSRFProtectionError, match="resolved to prohibited IP"):
        resolve_and_validate_host("evil-internal.example.com")

    # Host resolving to dual-homed IP (one public, one private)
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 80)),
    ]
    with pytest.raises(SSRFProtectionError, match="resolved to prohibited IP"):
        resolve_and_validate_host("split-dns.example.com")

    # Valid public host
    mock_getaddrinfo.return_value = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
    ]
    ips = resolve_and_validate_host("example.com")
    assert ips == ["93.184.216.34"]


# ---------------------------------------------------------------------------
# SSRF Client Protocol & Redirect Safety Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ssrf_client_scheme_and_userinfo_validation():
    """Verify dangerous schemes and userinfo in URLs are rejected."""
    client = SSRFSafeClient()

    # Reject non-http(s) schemes
    with pytest.raises(SSRFProtectionError, match="Unsupported or dangerous URI scheme"):
        await client.get("file:///etc/passwd")

    with pytest.raises(SSRFProtectionError, match="Unsupported or dangerous URI scheme"):
        await client.get("gopher://127.0.0.1:70")

    with pytest.raises(SSRFProtectionError, match="Unsupported or dangerous URI scheme"):
        await client.get("ftp://example.com/file.txt")

    # Reject userinfo
    with pytest.raises(SSRFProtectionError, match="URLs containing userinfo"):
        await client.get("http://admin:secret@example.com")


@pytest.mark.asyncio
@patch("socket.getaddrinfo")
async def test_ssrf_client_blocks_redirect_to_private_ip(mock_getaddrinfo):
    """Verify step-by-step redirect inspection catches malicious internal redirects."""
    client = SSRFSafeClient()

    # Initial target resolves to public IP
    mock_getaddrinfo.side_effect = [
        # First query: example.com -> 93.184.216.34
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))],
    ]

    # Mock response: 302 redirect to metadata IP 169.254.169.254
    redirect_resp = httpx.Response(
        status_code=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        request=httpx.Request("GET", "http://example.com"),
    )

    with patch("httpx.AsyncClient.request", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = redirect_resp

        with pytest.raises(SSRFProtectionError, match="prohibited or private"):
            await client.get("http://example.com/redirect")


# ---------------------------------------------------------------------------
# Circuit Breaker Lifecycle Tests
# ---------------------------------------------------------------------------

def test_circuit_breaker_state_transitions():
    """Verify CircuitBreaker trips to OPEN on threshold failures and recovers via HALF_OPEN."""
    cb = CircuitBreaker(failure_threshold=3, cooldown_seconds=0.1)

    assert cb.state == CircuitState.CLOSED
    assert cb.allow_request() is True

    # 1 failure
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_failures == 1

    # 2 failures
    cb.record_failure()
    assert cb.state == CircuitState.CLOSED

    # 3 failures -> trips to OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.total_trips == 1
    assert cb.allow_request() is False

    # Wait for cooldown to expire
    time.sleep(0.15)

    # Cooldown elapsed -> transitions to HALF_OPEN probe
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Probe failure -> immediately returns to OPEN
    cb.record_failure()
    assert cb.state == CircuitState.OPEN
    assert cb.total_trips == 2

    # Wait again and test recovery
    time.sleep(0.15)
    assert cb.allow_request() is True
    assert cb.state == CircuitState.HALF_OPEN

    # Probe success -> recovers to CLOSED
    cb.record_success()
    assert cb.state == CircuitState.CLOSED
    assert cb.consecutive_failures == 0


# ---------------------------------------------------------------------------
# URLhaus Provider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_urlhaus_provider_threat_hit():
    """Verify URLhaus adapter correctly processes verified threat hits."""
    provider = URLhausProvider(base_url="https://urlhaus-api.abuse.ch/v1")

    mock_resp = httpx.Response(
        status_code=200,
        json={
            "query_status": "ok",
            "id": "123456",
            "url_status": "online",
            "threat": "malware_download",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123456/",
            "tags": ["phishing", "trojan"],
            "date_added": "2026-11-14",
            "reporter": "security_researcher",
        },
        request=httpx.Request("POST", "https://urlhaus-api.abuse.ch/v1/url/"),
    )

    with patch.object(provider.ssrf_client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        result = await provider.lookup_url("http://malicious-site.example.com/payload.exe")

        assert result.provider_name == "urlhaus"
        assert result.is_threat is True
        assert result.threat_type == "phishing"  # Mapped from tags
        assert result.severity == "critical"     # "online" url_status -> critical
        assert result.confidence == 0.95
        assert result.reference_url == "https://urlhaus.abuse.ch/url/123456/"
        assert result.details["url_status"] == "online"


@pytest.mark.asyncio
async def test_urlhaus_provider_no_results():
    """Verify URLhaus adapter handles clean/unknown URL status."""
    provider = URLhausProvider()

    mock_resp = httpx.Response(
        status_code=200,
        json={"query_status": "no_results"},
        request=httpx.Request("POST", "https://urlhaus-api.abuse.ch/v1/url/"),
    )

    with patch.object(provider.ssrf_client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        result = await provider.lookup_url("https://clean-site.example.com")

        assert result.provider_name == "urlhaus"
        assert result.is_threat is False
        assert result.confidence == 0.0
        assert result.details["query_status"] == "no_results"


# ---------------------------------------------------------------------------
# PhishTank Provider Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_phishtank_provider_verified_phish():
    """Verify PhishTank adapter parses verified active phishing results."""
    provider = PhishTankProvider(api_key="test_key")

    mock_resp = httpx.Response(
        status_code=200,
        json={
            "meta": {"status": "success"},
            "results": {
                "url": "http://paypal-security-update.xyz",
                "in_database": True,
                "phish_id": "78910",
                "phish_detail_page": "http://www.phishtank.com/phish_detail.php?phish_id=78910",
                "verified": True,
                "verified_at": "2026-11-14T08:00:00+00:00",
                "valid": True,
            },
        },
        request=httpx.Request("POST", "https://checkurl.phishtank.com/checkurl/"),
    )

    with patch.object(provider.ssrf_client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        result = await provider.lookup_url("http://paypal-security-update.xyz")

        assert result.provider_name == "phishtank"
        assert result.is_threat is True
        assert result.threat_type == "phishing"
        assert result.severity == "critical"
        assert result.confidence == 0.98
        assert result.reference_url == "http://www.phishtank.com/phish_detail.php?phish_id=78910"


@pytest.mark.asyncio
async def test_phishtank_provider_not_found():
    """Verify PhishTank adapter returns clean result when not found."""
    provider = PhishTankProvider()

    mock_resp = httpx.Response(
        status_code=200,
        json={
            "results": {
                "in_database": False,
            }
        },
        request=httpx.Request("POST", "https://checkurl.phishtank.com/checkurl/"),
    )

    with patch.object(provider.ssrf_client, "post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp

        result = await provider.lookup_url("http://safe-domain.example.com")

        assert result.provider_name == "phishtank"
        assert result.is_threat is False
        assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# Threat Intelligence Service Orchestration Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_threat_intelligence_service_aggregation():
    """Verify concurrent query aggregation across multiple provider adapters."""
    mock_urlhaus = URLhausProvider()
    mock_phishtank = PhishTankProvider()

    # Mock urlhaus as clean
    async def mock_urlhaus_lookup(url: str):
        return ProviderResult(
            provider_name="urlhaus",
            is_threat=False,
            confidence=0.0,
            query_time_ms=12.0,
        )

    # Mock phishtank as confirmed phish
    async def mock_phishtank_lookup(url: str):
        return ProviderResult(
            provider_name="phishtank",
            is_threat=True,
            threat_type="phishing",
            severity="critical",
            confidence=0.98,
            reference_url="https://phishtank.com/123",
            query_time_ms=25.0,
        )

    mock_urlhaus.lookup_url = mock_urlhaus_lookup
    mock_phishtank.lookup_url = mock_phishtank_lookup

    service = ThreatIntelligenceService(providers=[mock_urlhaus, mock_phishtank])
    enrichment = await service.check_url("http://paypal-scam.xyz")

    assert enrichment.is_threat is True
    assert enrichment.threat_type == "phishing"
    assert enrichment.highest_severity == "critical"
    assert enrichment.highest_confidence == 0.98
    assert "phishtank" in enrichment.confirmed_sources
    assert "urlhaus" not in enrichment.confirmed_sources
    assert len(enrichment.provider_results) == 2
    assert "phishtank: Confirmed phishing" in (enrichment.evidence_summary or "")


@pytest.mark.asyncio
async def test_threat_intelligence_service_resilience_to_failures():
    """Verify that a failing or timing-out provider does not block other providers or crash the service."""
    failing_provider = URLhausProvider()
    working_provider = PhishTankProvider()

    # Failing provider raises exception
    async def mock_failing_lookup(url: str):
        raise httpx.ConnectTimeout("Connection to URLhaus timed out")

    # Working provider succeeds
    async def mock_working_lookup(url: str):
        return ProviderResult(
            provider_name="phishtank",
            is_threat=False,
            confidence=0.0,
            query_time_ms=10.0,
        )

    failing_provider.lookup_url = mock_failing_lookup
    working_provider.lookup_url = mock_working_lookup

    service = ThreatIntelligenceService(providers=[failing_provider, working_provider])
    enrichment = await service.check_url("https://example.com")

    # Service survives and returns result
    assert enrichment.is_threat is False
    assert "phishtank" in enrichment.provider_results
    assert "urlhaus" in enrichment.provider_results
    assert enrichment.provider_results["phishtank"].error is None
    assert "Connection to URLhaus timed out" in (enrichment.provider_results["urlhaus"].error or "")
    # Check that failure counter incremented on failing provider's circuit breaker
    assert failing_provider.circuit_breaker.consecutive_failures == 1
