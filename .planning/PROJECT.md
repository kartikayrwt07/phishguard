# PhishGuard — Hybrid Browser-Based Phishing Detection & Protection Platform

## What This Is

PhishGuard is a production-oriented, defense-in-depth cybersecurity platform that combines a Chrome Manifest V3 extension, a FastAPI modular monolith backend, and a React administrative console. It protects users from sophisticated phishing, credential harvesting, and brand impersonation attacks through 7-layer explainable risk scoring, real-time heuristic analysis, external threat intelligence feeds, and reproducible machine learning classification.

## Core Value

Accurately detect and disrupt deceptive web destinations and credential harvesting attempts in real-time, delivering explainable risk evidence while remaining fully functional offline and rigorously defending user privacy.

## Requirements

### Validated

(None yet — milestone 1 in progress)

### Active

- [ ] **SEC-01**: Chrome Manifest V3 extension packaging with local offline heuristic engine (<15ms evaluation).
- [ ] **SEC-02**: DeclarativeNetRequest (DNR) dynamic rule management for pre-emptive zero-leak blocking of confirmed threats.
- [ ] **SEC-03**: Safe, privacy-preserving DOM credential indicator analysis (password presence, cross-origin form actions, hidden iframes) without collecting user input, form data, or full HTML.
- [ ] **SEC-04**: 7-layer detection engine combining URL lexical features, brand homoglyph matching, domain/DNS metadata, DOM indicators, threat feeds, ML inference, and explainable scoring.
- [ ] **SEC-05**: FastAPI modular monolith with Argon2id password hashing, JWT authentication, and strict server-side RBAC.
- [ ] **SEC-06**: Threat intelligence provider adapters (URLhaus, PhishTank, Safe Browsing) with circuit breakers, rate limiting, and SSRF-safe HTTP client with DNS pinning.
- [ ] **SEC-07**: Scikit-learn reproducible training and inference pipeline with domain-level train/test separation to eliminate data leakage.
- [ ] **SEC-08**: React + TypeScript admin dashboard with Recharts, TanStack Query, scan explorer, feed synchronization telemetry, and user report triage.
- [ ] **SEC-09**: PostgreSQL persistence with SQLAlchemy 2.0, Alembic migrations, UTC timestamps, and UUID primary keys.

### Out of Scope

- Synchronous pre-render cancellation for unseen URLs without DNR rules — Chrome MV3 architectural limitation; mitigated with fast-path shroud and interstitial redirect.
- Microservice orchestration — Modular monolith chosen for maintainability and direct service boundaries without distributed complexity.
- Full page DOM tree transmission or HTML harvesting — Excluded to guarantee user privacy and avoid transmitting sensitive content.
- Credential or form-value logging — Explicitly forbidden; PhishGuard collects only structural signals.

## Context

- **Platform Target**: Google Chrome (Manifest V3), Python 3.12+ (tested with Python 3.11/3.14 on Windows), Node.js v24.
- **Threat Landscape**: Phishing kits using homoglyphs, brand keyword hijacking, free dynamic DNS/cloud hosting, and obfuscated login forms.
- **Environment**: Windows 11 host with Git repository; local test compatibility with SQLite alongside production PostgreSQL target.

## Constraints

- **Manifest V3**: No remotely hosted code; background service worker must survive termination; state persisted in `chrome.storage.local`.
- **Privacy & Security**: Zero secret collection; all backend external HTTP calls must enforce SSRF prevention and DNS pinning.
- **Explainability**: Every detection decision must return an itemized list of contributing evidence and score weights.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Monorepo Architecture | Consolidates backend, extension, dashboard, and ML pipelines with unified linting and testing | ✓ Good |
| Modular Monolith Backend | Clear service boundaries without distributed microservice operational overhead | ✓ Good |
| Backend ML Inference | Keeps extension bundle lightweight, preserves memory, allows instant model updates | ✓ Good |
| Dual DB Strategy in Dev | PostgreSQL target with SQLite compatibility for isolated, rapid unit testing | ✓ Good |
| SSRF-Safe Transport | DNS pre-resolution and IP pinning prevents TOCTOU rebinding and internal subnet access | ✓ Good |

---
*Last updated: 2026-11-14 after Project Discovery & Requirements Approval*

