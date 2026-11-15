# Requirements: PhishGuard

**Defined:** 2026-11-14  
**Core Value:** Accurately detect and disrupt deceptive web destinations and credential harvesting attempts in real-time, delivering explainable risk evidence while remaining fully functional offline and rigorously defending user privacy.

## v1 Requirements

### 1. Extension (EXT)
- [ ] **EXT-01**: Manifest V3 compliant architecture with background service worker resilient to termination and restart.
- [ ] **EXT-02**: Offline local URL feature extraction and rule-based heuristic scoring completing in under 15ms.
- [ ] **EXT-03**: `chrome.declarativeNetRequest` (DNR) integration to block known malicious URLs and hostnames synchronously before network transmission.
- [ ] **EXT-04**: Fast-path DOM visual shroud injected at `document_start` on suspicious navigations to prevent immediate credential entry.
- [ ] **EXT-05**: Warning interstitial navigation page (`warning.html`) displaying threat classification, risk score, and detailed evidence breakdown.
- [ ] **EXT-06**: Privacy-preserving DOM signal extractor collecting only structural form metadata (password presence, form action targets, hidden iframes) with zero input values, cookies, or secrets.
- [ ] **EXT-07**: Extension popup UI built with React + Vite + Tailwind showing current tab security posture, risk meter, and allowlist controls.
- [ ] **EXT-08**: Multi-tier client cache storing recent verdicts in `chrome.storage.local` with configurable TTLs.

### 2. Backend & Core API (API)
- [ ] **API-01**: FastAPI modular monolith structured into `core`, `api`, `models`, `schemas`, `repositories`, `services`, `detection`, `intelligence`, and `workers`.
- [ ] **API-02**: Argon2id password hashing and JWT authentication lifecycle with access and refresh tokens.
- [ ] **API-03**: Server-side Role-Based Access Control (RBAC) enforcing `admin`, `analyst`, and `user` privileges.
- [ ] **API-04**: Versioned `/api/v1` REST endpoints for URL scanning, DOM signal enrichment, threat feed management, scan history, and user reports.
- [ ] **API-05**: PostgreSQL database persistence using SQLAlchemy 2.0 with UUID primary keys and UTC timestamps.
- [ ] **API-06**: Alembic database migrations tracking all schema revisions.
- [ ] **API-07**: Structured JSON logging and centralized error handling with no unhandled internal exceptions exposed.

### 3. Detection Engine & Scoring (DET)
- [ ] **DET-01**: Layer 1 URL Analysis: safe URL normalization, lexical features, entropy, suspicious delimiters, Punycode/IDN parsing, and TLD reputation.
- [ ] **DET-02**: Layer 2 Brand Impersonation: Levenshtein distance matching, homoglyph replacement mapping, and brand keyword placement against a curated brand dictionary.
- [ ] **DET-03**: Layer 3 Domain & DNS Intelligence: RDAP age inspection, nameserver verification, and reputation scoring (treating missing data as unknown, not malicious).
- [ ] **DET-04**: Layer 4 DOM Indicator Evaluation: form action cross-origin validation, IP form destinations, and login input presence scoring.
- [ ] **DET-05**: Layer 5 Threat Intelligence Adapters: URLhaus, PhishTank, and Safe Browsing integrations with circuit breakers and error isolation.
- [ ] **DET-06**: Layer 6 ML Classifier: Scikit-learn inference pipeline returning phishing probability.
- [ ] **DET-07**: Layer 7 Explainable Risk Scoring Engine: composite score (0-100), categorical verdict (`SAFE`, `SUSPICIOUS`, `PHISHING`, `UNKNOWN`), confidence score, and itemized evidence list.
- [ ] **DET-08**: High-priority override policy for confirmed threat feed matches and explicit user/enterprise allowlists.

### 4. Machine Learning Pipeline (ML)
- [ ] **ML-01**: Curated and balanced URL dataset generation with verified legitimate and phishing samples.
- [ ] **ML-02**: Domain-level (eTLD+1) grouped train/validation/test splitting to strictly prevent cross-split data leakage.
- [ ] **ML-03**: Reproducible feature extraction pipeline generating 30+ lexical, structural, and statistical features.
- [ ] **ML-04**: Model benchmark comparing Logistic Regression, Random Forest, and Gradient Boosted trees.
- [ ] **ML-05**: Automated evaluation reporting measuring Precision, Recall, F1-score, False Positive Rate (FPR), False Negative Rate (FNR), confusion matrix, and inference latency.
- [ ] **ML-06**: Model artifact versioning with Joblib serialization and model rollback capability.

### 5. Admin Dashboard (DASH)
- [ ] **DASH-01**: React + TypeScript + Vite administrative dashboard with Tailwind CSS and accessible components.
- [ ] **DASH-02**: Secure authentication flow with token refresh and client-side route guards matching server-side RBAC.
- [ ] **DASH-03**: Overview dashboard with aggregate security posture metrics, threat trends, and detection charts (Recharts).
- [ ] **DASH-04**: Scan Explorer enabling real-time filtering, search, and deep-dive inspection of scan evidence.
- [ ] **DASH-05**: Threat Intelligence Manager displaying provider health, feed freshness, and sync controls.
- [ ] **DASH-06**: Detection Rule Manager for adjusting heuristic weights, brand targets, and allowlist entries.
- [ ] **DASH-07**: User Report Triage interface for investigating user-submitted false-positive and false-negative reports.
- [ ] **DASH-08**: Audit Log viewer tracking all administrative and system operations.

### 6. Security & Infrastructure (SEC)
- [ ] **SEC-01**: SSRF-safe HTTP client with DNS pre-resolution, private/reserved IP blocking (RFC 1918, metadata `169.254.169.254`, loopback), and IP socket pinning.
- [ ] **SEC-02**: Content Security Policy (CSP) enforcement on extension pages and admin dashboard.
- [ ] **SEC-03**: Strict input validation using Pydantic v2 schemas and sanitized database queries.
- [ ] **SEC-04**: Production Docker Compose configuration packaging backend, PostgreSQL, Redis, and dashboard reverse proxy.
- [ ] **SEC-05**: Automated test harness with Pytest (backend), Vitest (extension and dashboard), and Playwright end-to-end integration tests.

## Out of Scope
- Full raw HTML storage or server-side page harvesting (rejected for privacy and legal liability).
- Synchronous blocking of arbitrary unseen URLs in Manifest V3 without DNR rules (technically infeasible in Chrome MV3).
- Plaintext password or form submission logging (strictly forbidden).

## Traceability Matrix

| Requirement | Phase / Milestone | Status |
|---|---|---|
| EXT-01, EXT-08 | M8 | Pending |
| EXT-02, EXT-03 | M9 | Pending |
| EXT-04, EXT-06 | M10 | Pending |
| EXT-07 | M11 | Pending |
| EXT-05 | M12 | Pending |
| API-01, API-07 | M2, M4 | Pending |
| API-02, API-03 | M4 | Pending |
| API-04 | M4, M11 | Pending |
| API-05, API-06 | M3 | Pending |
| DET-01 | M5 | Pending |
| DET-02, DET-04, DET-07, DET-08 | M6 | Pending |
| DET-03, DET-05 | M7 | Pending |
| DET-06 | M14 | Pending |
| ML-01, ML-02, ML-03 | M13 | Pending |
| ML-04, ML-05, ML-06 | M14 | Pending |
| DASH-01, DASH-02 | M15 | Pending |
| DASH-03, DASH-04, DASH-06 | M16 | Pending |
| DASH-05, DASH-07, DASH-08 | M17 | Pending |
| SEC-01 | M7, M19 | Pending |
| SEC-02, SEC-03 | M4, M15, M19 | Pending |
| SEC-04 | M2, M20 | Pending |
| SEC-05 | M2, M18, M19 | Pending |

**Coverage:**
- Total v1 Requirements: 34
- Mapped to Milestones: 34 (100% coverage)
- Unmapped: 0

---
*Requirements defined: 2026-11-14*

