---
phase: PHISH-07-threat-intelligence-provider-architecture
plan: "01"
subsystem: intelligence
tags: [threat-intelligence, ssrf-protection, dns-pinning, toctou, circuit-breaker, urlhaus, phishtank]

requires:
  - phase: PHISH-06-rule-engine-and-explainable-risk-scoring
    provides: RiskEngine, override policies, and evidence schemas
provides:
  - SSRF-safe HTTP client with DNS pre-resolution, private/link-local/metadata IP rejection, and IP socket pinning
  - CircuitBreaker with CLOSED, OPEN, and HALF_OPEN states protecting against external feed outages
  - URLhausProvider adapter parsing malicious URL and domain queries
  - PhishTankProvider adapter parsing verified community phishing indicators
  - ThreatIntelligenceService coordinating concurrent queries across providers with timeout budgets
affects: [backend, intelligence, detection, security]

tech-stack:
  added: []
  patterns: [SSRF defense-in-depth, DNS rebinding mitigation via socket IP pinning, Circuit Breaker pattern, concurrent timeout budgets]

key-files:
  created:
    - backend/app/intelligence/ssrf_client.py
    - backend/app/intelligence/base.py
    - backend/app/intelligence/urlhaus.py
    - backend/app/intelligence/phishtank.py
    - backend/app/intelligence/service.py
    - backend/tests/test_threat_intel.py
  modified:
    - backend/app/intelligence/__init__.py

key-decisions:
  - "Pin pre-resolved and validated IP directly in HTTP transport with Host header and SNI hostname extension to defeat DNS rebinding (TOCTOU)"
  - "Disable automated redirects; evaluate each redirect hop step-by-step against SSRF filters to prevent internal redirection attacks"
  - "Reject userinfo in URLs to prevent URI parser confusion attacks"
  - "Enforce CircuitBreaker per provider to isolate downstream detection latency from upstream feed outages"
  - "Coordinate concurrent lookups using asyncio.gather with an overall timeout budget and return_exceptions=True"

patterns-established:
  - "SSRFProtectionError raised whenever private, loopback, link-local, or cloud metadata addresses are targeted"
  - "Standardized ProviderResult and ProviderHealth dataclasses across all threat adapters"
  - "ThreatEnrichmentResult aggregating multiple feed outputs into evidence suitable for RiskEngine overrides"

requirements-completed:
  - DET-03
  - DET-05
  - SEC-01

duration: 25min
completed: 2026-11-14
---

# Phase 07: Threat Intelligence Provider Architecture Summary

**Implemented SSRF-safe HTTP client with DNS pre-resolution and IP socket pinning, Circuit Breaker fault isolation, URLhaus and PhishTank adapters, and concurrent orchestration service.**

## Accomplishments
- **SSRF-Safe HTTP Client (`ssrf_client.py`)**:
  - Implemented pre-DNS resolution validating all resolved IPv4/IPv6 addresses against RFC 1918, RFC 3927 (link-local), cloud metadata (`169.254.169.254`), loopback (`127.0.0.0/8`, `::1`), carrier-grade NAT, and test networks.
  - Mitigates DNS rebinding (TOCTOU) by pinning the validated IP address directly into the connection socket while providing the original `Host` header and `sni_hostname` TLS extension.
  - Step-by-step redirect inspection ensuring redirect responses cannot bypass SSRF filters.
  - Strict scheme whitelisting (`http`, `https`) and userinfo rejection.
- **Circuit Breaker Fault Isolation (`base.py`)**:
  - Implemented `CircuitBreaker` with standard three-state lifecycle: `CLOSED`, `OPEN`, and `HALF_OPEN`.
  - Configurable failure threshold and cooldown period; fast-fails during provider outages without incurring network latency.
  - Standardized `ProviderResult` and `ProviderHealth` dataclasses.
- **Provider Adapters (`urlhaus.py`, `phishtank.py`)**:
  - `URLhausProvider`: Queries abuse.ch URLhaus API for verified malware/phishing distributions; handles `query_status` (`ok`, `no_results`), tags, and status.
  - `PhishTankProvider`: Queries PhishTank API for community-verified phishing submissions with API key authentication and confidence weighting.
  - Both adapters encapsulate network errors within their circuit breakers.
- **Threat Intelligence Service (`service.py`)**:
  - Coordinates parallel lookups across all enabled providers using `asyncio.gather` with an overall timeout budget.
  - Aggregates provider detections into `ThreatEnrichmentResult`, ranking severity and composing explainable evidence for `RiskEngine` threat feed overrides.
- **Automated Verification**:
  - Authored `backend/tests/test_threat_intel.py` with 12 tests covering private IP detection, DNS mock validation, redirect protection, circuit breaker transitions, adapter parsing, and service aggregation.
  - All 12 threat intel tests and 43 total backend tests pass.

