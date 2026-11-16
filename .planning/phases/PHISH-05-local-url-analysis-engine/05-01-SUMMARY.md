---
phase: PHISH-05-local-url-analysis-engine
plan: "01"
subsystem: detection
tags: [url-parser, feature-extraction, shannon-entropy, punycode, ip-hosts]

requires:
  - phase: PHISH-04-backend-configuration-authentication-and-rbac
    provides: FastAPI app factory, security core, and test harness
provides:
  - RFC 3986-compliant URL normalizer and canonicalizer
  - Detection of raw IPv4, IPv6, and hex/decimal obfuscated hostnames
  - IDNA/Punycode decoding
  - Multi-part TLD extraction (.co.uk, .com.au, etc.)
  - 30+ lexical, structural, statistical, and Shannon entropy feature extraction engine
affects: [backend, detection, ml, extension]

tech-stack:
  added: []
  patterns: [RFC 3986 canonicalization, Shannon information entropy, heuristic keyword scanning]

key-files:
  created:
    - backend/app/detection/url_parser.py
    - backend/app/detection/features.py
    - backend/app/detection/__init__.py
    - backend/tests/test_url_analysis.py

key-decisions:
  - "Default scheme to http if protocol is absent"
  - "Strip default ports (80 for http, 443 for https) and sort query parameters for deterministic caching"
  - "Extract Shannon entropy across full URL, hostname, and path separately"
  - "Count delimiter characters from raw input to catch userinfo @ and unencoded evasion techniques"
  - "Support multi-part TLDs (.co.uk, .com.au, .gov.in, etc.) in domain separation"

patterns-established:
  - "ParsedURL immutable dataclass for standardized URL representations"
  - "URLFeatures immutable dataclass with to_dict() for ML pipeline and rule evaluation"

requirements-completed:
  - DET-01

duration: 20min
completed: 2026-11-14
---

# Phase 05: Local URL Analysis Engine Summary

**Implemented RFC 3986 URL normalizer, Punycode/IP decoder, and 30+ lexical and Shannon entropy feature extraction engine.**

## Accomplishments
- Implemented `backend/app/detection/url_parser.py` featuring `URLNormalizer` and `ParsedURL`:
  - Scheme lowercasing and validation (defaulting to http).
  - Port stripping for standard web ports (80, 443).
  - Multi-part TLD parsing (properly handling `.co.uk`, `.com.au`, `.gov.in`, etc.).
  - IPv4 and IPv6 detection, including bracket notation and hex/decimal encoded IPs (`0x7f000001`, `2130706433`).
  - Punycode IDNA decoding (`xn--pple-43d.com` -> Unicode).
  - Deterministic query parameter sorting for caching.
- Implemented `backend/app/detection/features.py` with `FeatureExtractor` and `URLFeatures`:
  - Calculates 30+ features covering structural lengths, 11 delimiter counts, subdomain depth, Shannon entropy (URL, host, path), character ratios (digits, vowels, consonants), consecutive consonants streak, high-risk TLD flags, and suspicious keyword detection.
- Authored test suite `backend/tests/test_url_analysis.py` covering standard normalization, multi-part TLDs, raw IPs, hex/dec IPs, Punycode, Shannon entropy calculation, phishing indicator detection, clean legitimate URLs, and malformed inputs.
- All 9 URL analysis tests and 21 total backend tests pass with 100% success.

