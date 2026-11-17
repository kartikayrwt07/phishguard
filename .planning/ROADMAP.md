# Roadmap: PhishGuard

## Overview

PhishGuard is built across 20 disciplined milestones grouped into 6 execution waves, progressing from foundational repository scaffolding and database models to detection engine heuristics, Manifest V3 browser protection, reproducible machine learning, administrative console, and production release preparation.

## Phases

- [x] **Phase 1: Requirements and Project Foundation** - Architecture decisions, GSD initialization, and baseline configuration
- [x] **Phase 2: Monorepo Structure and Development Infrastructure** - Monorepo setup, linters, pre-commit hooks, Vitest and Pytest harnesses
- [x] **Phase 3: Database Models and Alembic Migrations** - Normalized PostgreSQL models with UUID PKs, UTC timestamps, and Alembic migrations
- [x] **Phase 4: Backend Configuration Authentication and RBAC** - FastAPI application factory, Argon2id hashing, JWT auth, and RBAC middleware
- [x] **Phase 5: Local URL Analysis Engine** - Safe URL parsing, 30+ lexical/entropy features, Punycode/homoglyph handling
- [ ] **Phase 6: Rule Engine and Explainable Risk Scoring** - Heuristic evaluation, brand similarity matching, explainable evidence generation
- [ ] **Phase 7: Threat Intelligence Provider Architecture** - Adapters for URLhaus/PhishTank, circuit breakers, SSRF-safe HTTP client
- [ ] **Phase 8: Extension Foundation and Manifest V3 Integration** - MV3 skeleton, persistent Service Worker lifecycle, typed message contracts
- [ ] **Phase 9: Extension URL Analysis and Local Caching** - Offline heuristic scoring (<15ms), local LRU cache in chrome.storage.local, DNR dynamic rules
- [ ] **Phase 10: DOM and Credential-Form Indicator Analysis** - Content script structural collector with zero-secret leakage
- [ ] **Phase 11: Backend Integration and Cloud Enrichment** - Extension-to-backend communication, device registration, and background enrichment
- [ ] **Phase 12: Warning Interstitial and Protection Controls** - Real-time visual shroud, standalone warning page, override handling
- [ ] **Phase 13: ML Dataset and Feature Engineering** - Curated benchmark dataset, domain-level leakage-free splitting, feature extractors
- [ ] **Phase 14: ML Model Training Evaluation and Versioning** - Logistic Regression vs Random Forest vs GBDT benchmark, automated evaluation report
- [ ] **Phase 15: Dashboard Foundation and Authentication** - React + TypeScript + Tailwind UI scaffold, TanStack Query, RBAC route guards
- [ ] **Phase 16: Scan Explorer and Threat Management** - Real-time scan log explorer, threat indicator drilldown, explainable evidence viewer
- [ ] **Phase 17: Feed Management Reporting and Audit Logs** - Threat feed sync monitor, user false-positive triage, system audit log table
- [ ] **Phase 18: End-to-End Integration Testing** - Playwright automated tests on simulated phishing pages, offline failover tests
- [ ] **Phase 19: Security Audit and Performance Tuning** - SSRF audit, XSS/CSP checks, memory profiling of extension Service Worker
- [ ] **Phase 20: Documentation Packaging and Release** - Production Docker Compose, extension zip build, OpenAPI spec export, release notes

## Phase Details

### Phase 1: Requirements and Project Foundation
**Goal**: Establish complete GSD project tracking, architectural standards, and baseline configuration.
**Depends on**: Nothing (Initial phase)
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-05
**Success Criteria** (what must be TRUE):
  1. .planning/ directory initialized with PROJECT.md, ROADMAP.md, REQUIREMENTS.md, STATE.md, and config.json.
  2. Master architecture document reviewed and approved.
  3. Git tracking active and initial documentation committed.
**Plans**: 1 plan

Plans:
- [x] 01-01: Initialize GSD project context, requirements traceability, and baseline repository configuration.

### Phase 2: Monorepo Structure and Development Infrastructure
**Goal**: Establish unified monorepo directory layout, TypeScript/Python dependencies, linting, formatting, and test runners.
**Depends on**: Phase 1
**Requirements**: API-01, SEC-04, SEC-05
**Success Criteria** (what must be TRUE):
  1. backend/, extension/, dashboard/, ml/, docker/, and docs/ directories scaffolded with valid package definitions.
  2. Pytest and Vitest runners execute cleanly.
  3. Pre-commit and linting configurations operational.
**Plans**: 1 plan

Plans:
- [x] 02-01: Scaffold monorepo packages, Python venv, Node dependencies, Vitest/Pytest test harnesses, and CI linting configs.

### Phase 3: Database Models and Alembic Migrations
**Goal**: Implement normalized PostgreSQL database schema with UUID primary keys and Alembic migration tracking.
**Depends on**: Phase 2
**Requirements**: API-05, API-06
**Success Criteria** (what must be TRUE):
  1. 13 core models defined in SQLAlchemy 2.0 (users, scans, scan_evidence, threat_indicators, threat_sources, etc.).
  2. Alembic migration scripts generate valid DDL.
  3. Automated database schema roundtrip tests pass.
**Plans**: 1 plan

Plans:
- [x] 03-01: Implement SQLAlchemy 2.0 ORM models, migration scripts, and test suite.

### Phase 4: Backend Configuration Authentication and RBAC
**Goal**: Provide secure backend application factory, Argon2id password hashing, JWT token lifecycle, and role-based access control.
**Depends on**: Phase 3
**Requirements**: API-01, API-02, API-03, API-04, API-07, SEC-02, SEC-03
**Success Criteria** (what must be TRUE):
  1. FastAPI app starts with structured logging and centralized exception handling.
  2. User registration and authentication endpoints issue signed JWTs with Argon2id hash verification.
  3. RBAC dependencies enforce admin, analyst, and user permissions with 403 Forbidden on unauthorized roles.
**Plans**: 1 plan

Plans:
- [x] 04-01: Implement FastAPI app factory, security core, JWT auth, and RBAC middleware.

### Phase 5: Local URL Analysis Engine
**Goal**: Implement fast, safe, standards-compliant URL normalization and 30+ lexical/entropy feature extractors.
**Depends on**: Phase 4
**Requirements**: DET-01
**Success Criteria** (what must be TRUE):
  1. Safe URL parser handles edge cases, IP addresses, Punycode/IDN, and complex query structures.
  2. 30+ features extracted with full test coverage.
**Plans**: 1 plan

Plans:
- [x] 05-01: Build URL normalizer, lexical parser, entropy calculators, and test suite.

### Phase 6: Rule Engine and Explainable Risk Scoring
**Goal**: Implement layered scoring engine, brand distance matching, and itemized evidence generation.
**Depends on**: Phase 5
**Requirements**: DET-02, DET-04, DET-07, DET-08
**Success Criteria** (what must be TRUE):
  1. Levenshtein and homoglyph brand impersonation detection against curated reference dataset.
  2. Composite scoring engine outputs categorical verdicts with itemized scoring evidence.
**Plans**: 1 plan

Plans:
- [x] 06-01: Build heuristic rule engine, brand similarity matcher, and risk scoring accumulator.

### Phase 7: Threat Intelligence Provider Architecture
**Goal**: Build isolated threat feed adapters with circuit breakers and SSRF-safe HTTP client.
**Depends on**: Phase 6
**Requirements**: DET-03, DET-05, SEC-01
**Success Criteria** (what must be TRUE):
  1. URLhaus and PhishTank adapters support timeouts, rate-limiting, and error isolation.
  2. SSRF-safe HTTP client blocks private IPs and pins DNS.
**Plans**: 1 plan

Plans:
- [x] 07-01: Implement threat provider interfaces, concrete adapters, and SSRF-safe network client.

### Phase 8: Extension Foundation and Manifest V3 Integration
**Goal**: Set up Chrome Manifest V3 extension skeleton with persistent Service Worker lifecycle and typed message bus.
**Depends on**: Phase 7
**Requirements**: EXT-01, EXT-08
**Success Criteria** (what must be TRUE):
  1. Extension loads into Chrome with MV3 manifest and least-privilege permissions.
  2. Service Worker state survives restarts using chrome.storage.local.
**Plans**: 1 plan

Plans:
- [x] 08-01: Build MV3 extension foundation, service worker lifecycle, and typed messaging bus.

### Phase 9: Extension URL Analysis and Local Caching
**Goal**: Implement client-side offline URL analysis and declarativeNetRequest blocking.
**Depends on**: Phase 8
**Requirements**: EXT-02, EXT-03
**Success Criteria** (what must be TRUE):
  1. Offline heuristic scoring executes in Service Worker in under 15ms.
  2. DNR dynamic rules block confirmed threat URLs synchronously.
**Plans**: 1 plan

Plans:
- [x] 09-01: Port lightweight URL heuristic engine to extension and wire DNR manager.

### Phase 10: DOM and Credential-Form Indicator Analysis
**Goal**: Implement privacy-preserving content script signal extractor.
**Depends on**: Phase 9
**Requirements**: EXT-04, EXT-06
**Success Criteria** (what must be TRUE):
  1. Content script detects password inputs, cross-origin form actions, and hidden iframes.
  2. Zero secrets or input values collected.
**Plans**: 1 plan

Plans:
- [x] 10-01: Implement content script DOM observer, typed signal messages, and visual holding shroud.

### Phase 11: Backend Integration and Cloud Enrichment
**Goal**: Connect extension to backend API for background risk enrichment.
**Depends on**: Phase 10
**Requirements**: EXT-07, API-04
**Success Criteria** (what must be TRUE):
  1. Service Worker communicates securely with backend API.
  2. React popup UI displays real-time score, threat tags, and allowlist toggle.
**Plans**: 1 plan

Plans:
- [x] 11-01: Build extension API client, React popup UI, and cloud enrichment flow.

### Phase 12: Warning Interstitial and Protection Controls
**Goal**: Build standalone warning page and bypass controls.
**Depends on**: Phase 11
**Requirements**: EXT-05
**Success Criteria** (what must be TRUE):
  1. Phishing navigations redirect to warning.html with explainable evidence.
  2. User can safely bypass with explicit warning confirmation or domain allowlisting.
**Plans**: 1 plan

Plans:
- [x] 12-01: Implement warning interstitial UI, proceed override handlers, and allowlist persistence.

### Phase 13: ML Dataset and Feature Engineering
**Goal**: Create curated, leakage-free training dataset and feature extraction pipeline.
**Depends on**: Phase 12
**Requirements**: ML-01, ML-02, ML-03
**Success Criteria** (what must be TRUE):
  1. Domain-level (eTLD+1) grouped splitting eliminates data leakage.
  2. 30+ features extracted consistently between ML pipeline and backend service.
**Plans**: 1 plan

Plans:
- [ ] 13-01: Implement dataset curation script, leakage-free splitters, and feature transformation pipelines.

### Phase 14: ML Model Training Evaluation and Versioning
**Goal**: Train, evaluate, and serialize baseline and tree-based classifiers.
**Depends on**: Phase 13
**Requirements**: DET-06, ML-04, ML-05, ML-06
**Success Criteria** (what must be TRUE):
  1. Benchmark report comparing Logistic Regression, Random Forest, and GBDT on holdout test set.
  2. Model exported with Joblib and integrated into backend detection pipeline.
**Plans**: 1 plan

Plans:
- [ ] 14-01: Train classifiers, generate metrics report, and integrate model inference into backend.

### Phase 15: Dashboard Foundation and Authentication
**Goal**: Build React + TypeScript admin dashboard foundation with secure auth and RBAC guards.
**Depends on**: Phase 14
**Requirements**: DASH-01, DASH-02, SEC-02
**Success Criteria** (what must be TRUE):
  1. Dashboard UI scaffolded with Tailwind and TanStack Query.
  2. Login flow and RBAC route protection active.
**Plans**: 1 plan

Plans:
- [ ] 15-01: Build admin dashboard shell, auth provider, layout, and protected routes.

### Phase 16: Scan Explorer and Threat Management
**Goal**: Implement real-time scan monitoring and threat indicator management in dashboard.
**Depends on**: Phase 15
**Requirements**: DASH-03, DASH-04, DASH-06
**Success Criteria** (what must be TRUE):
  1. Overview charts show scan volumes and threat distribution.
  2. Scan explorer allows searching, filtering, and deep-dive evidence inspection.
**Plans**: 1 plan

Plans:
- [ ] 16-01: Build overview metric cards, Recharts visualizations, and scan explorer table.

### Phase 17: Feed Management Reporting and Audit Logs
**Goal**: Implement threat intelligence feed monitoring, user report triage, and audit log viewer.
**Depends on**: Phase 16
**Requirements**: DASH-05, DASH-07, DASH-08
**Success Criteria** (what must be TRUE):
  1. Feed sync status and manual sync trigger operational.
  2. User reports and audit log tables display paginated records.
**Plans**: 1 plan

Plans:
- [ ] 17-01: Build feed manager, user report review panel, and audit log viewer.

### Phase 18: End-to-End Integration Testing
**Goal**: Build automated end-to-end integration test suite on simulated phishing fixtures.
**Depends on**: Phase 17
**Requirements**: SEC-05
**Success Criteria** (what must be TRUE):
  1. Playwright tests verify detection flow from navigation to warning interstitial.
  2. Offline failover tests prove extension operates when backend is down.
**Plans**: 1 plan

Plans:
- [ ] 18-01: Build local simulated phishing test fixtures and Playwright end-to-end test suites.

### Phase 19: Security Audit and Performance Tuning
**Goal**: Perform comprehensive security audit, SSRF verification, and performance profiling.
**Depends on**: Phase 18
**Requirements**: SEC-01, SEC-02, SEC-03
**Success Criteria** (what must be TRUE):
  1. SSRF and DNS rebinding protections verified against hostile targets.
  2. Extension Service Worker memory and latency benchmarks verified under 15ms.
**Plans**: 1 plan

Plans:
- [ ] 19-01: Run automated security test suite, memory profiling, and query optimizations.

### Phase 20: Documentation Packaging and Release
**Goal**: Package production containers, extension bundle, and release documentation.
**Depends on**: Phase 19
**Requirements**: SEC-04
**Success Criteria** (what must be TRUE):
  1. Production Docker Compose verified.
  2. Chrome extension packaged into zip artifact.
  3. OpenAPI specifications and deployment README published.
**Plans**: 1 plan

Plans:
- [ ] 20-01: Build Docker packaging, release artifacts, and comprehensive user/developer documentation.

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → ... → 20

| Phase | Plans Complete | Status | Completed |
|---|---|---|---|
| 1. Requirements and Project Foundation | 1/1 | Complete | 2026-11-14 |
| 2. Monorepo Structure and Development Infrastructure | 1/1 | Complete | 2026-11-14 |
| 3. Database Models and Alembic Migrations | 1/1 | Complete | 2026-11-14 |
| 4. Backend Configuration Authentication and RBAC | 1/1 | Complete | 2026-11-14 |
| 5. Local URL Analysis Engine | 1/1 | Complete | 2026-11-14 |
| 6. Rule Engine and Explainable Risk Scoring | 0/1 | Not started | - |
| 7. Threat Intelligence Provider Architecture | 0/1 | Not started | - |
| 8. Extension Foundation and Manifest V3 Integration | 0/1 | Not started | - |
| 9. Extension URL Analysis and Local Caching | 0/1 | Not started | - |
| 10. DOM and Credential-Form Indicator Analysis | 0/1 | Not started | - |
| 11. Backend Integration and Cloud Enrichment | 0/1 | Not started | - |
| 12. Warning Interstitial and Protection Controls | 0/1 | Not started | - |
| 13. ML Dataset and Feature Engineering | 0/1 | Not started | - |
| 14. ML Model Training Evaluation and Versioning | 0/1 | Not started | - |
| 15. Dashboard Foundation and Authentication | 0/1 | Not started | - |
| 16. Scan Explorer and Threat Management | 0/1 | Not started | - |
| 17. Feed Management Reporting and Audit Logs | 0/1 | Not started | - |
| 18. End-to-End Integration Testing | 0/1 | Not started | - |
| 19. Security Audit and Performance Tuning | 0/1 | Not started | - |
| 20. Documentation Packaging and Release | 0/1 | Not started | - |

---
*Roadmap generated: 2026-11-14*
