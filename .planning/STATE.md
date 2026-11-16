# Project State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-11-14)

**Core value:** Accurately detect and disrupt deceptive web destinations and credential harvesting attempts in real-time, delivering explainable risk evidence while remaining fully functional offline and rigorously defending user privacy.  
**Current focus:** Phase 11: Backend Integration and Cloud Enrichment

## Current Position

Phase: 11 of 20 (Phase 11: Backend Integration and Cloud Enrichment)  
Plan: 0 of 1 in current phase  
Status: Ready to plan  
Last activity: 2026-11-14 — Completed Phase 10 (M10). Content script structural DOM extractor with zero-secret guarantees, Shadow DOM warning holding shroud, and background score enrichment verified passing (82/82 total tests passing across monorepo).

Progress: [▓▓▓▓▓▓▓▓▓▓] 50%

## Accumulated Context

### Decisions

- [M1]: Greenfield monorepo architecture chosen with clear module boundaries (`backend/`, `extension/`, `dashboard/`, `ml/`, `docker/`).
- [M1]: Scikit-learn model inference placed on backend to preserve extension lightweightness; extension retains local offline heuristic engine.
- [M1]: Dual DB strategy: PostgreSQL for production/migrations, SQLite support for hermetic rapid unit tests in dev environments.
- [M1]: SSRF prevention: backend external HTTP client requires pre-DNS resolution and socket IP pinning against RFC 1918 and metadata endpoints.
- [M2]: Established root npm workspaces for `extension` and `dashboard` with unified testing script `npm run test:all`.
- [M2]: Configured Python 3.11 virtual environment with Pytest and strict modular monolith package resolution.
- [M3]: Implemented GUID TypeDecorator and dialect-aware JSONType (JSONB in PostgreSQL, JSON in SQLite).
- [M3]: All 13 domain models configured with UUID primary keys and UTC timezone-aware timestamps.
- [M4]: Argon2id password hashing and JWT token lifecycle (access + refresh tokens).
- [M4]: Server-side RBAC with require_role dependency enforcing Admin vs Analyst vs User permissions.
- [M5]: Safe URL parsing strips default ports (80, 443), handles multi-part TLDs, and normalizes paths.
- [M5]: Feature extraction extracts 34 distinct structural, lexical, entropy, and statistical indicators.
- [M6]: Curated reference catalog of 16 top brands with legitimate domain exemptions to eliminate self-flagging.
- [M6]: Tokenized hyphen-separated domain labels to catch compound lookalike phishing (e.g., paypa1-account-verify.xyz).
- [M6]: DOM structural evaluator inspects credential targets and hidden iframes without collecting password values, inputs, or cookies.
- [M6]: Layer 7 RiskEngine outputs categorical verdicts, 0-100 normalized score, confidence, and itemized ScanEvidenceItem records.
- [M6]: Deterministic override policies enforce immediate SAFE (0) on allowlist and PHISHING (100) on verified threat feeds.
- [M7]: SSRF-safe client pre-resolves DNS and pins the validated IP directly in HTTP transport with Host header and SNI hostname extension to defeat DNS rebinding (TOCTOU).
- [M7]: Automated redirects disabled in SSRF client; step-by-step redirect validation prevents internal redirect hops to metadata or private IPs.
- [M7]: In-memory CircuitBreaker (CLOSED, OPEN, HALF_OPEN) isolates downstream detection latency from upstream feed outages.
- [M7]: ThreatIntelligenceService coordinates concurrent queries with an overall timeout budget and aggregates explainable evidence.
- [M8]: Extension configured for Manifest V3 with least-privilege permissions (`storage`, `tabs`, `declarativeNetRequest`, `activeTab`).
- [M8]: StorageManager wraps `chrome.storage.local` with in-memory fallback for testing, UUID deviceId generation, and 15-minute TTL scan cache eviction.
- [M8]: Discriminated union message bus establishes strongly typed communication across service worker, popup, options, and content scripts.
- [M8]: Vite multi-entry build configured to compile standalone `background.js` and `content.js` scripts alongside HTML bundles.
- [M9]: Preserved pre-IDNA Unicode host in client-side URL normalizer to detect non-ASCII homoglyphs directly.
- [M9]: Implemented sub-15ms offline HeuristicEngine (<1ms average) evaluating Shannon entropy, lexical indicators, and brand catalog lookalikes.
- [M9]: Guaranteed immediate SAFE (score 0) exemption for legitimate brand root and subdomains.
- [M9]: Implemented DNRRuleManager for synchronous declarativeNetRequest blocking and warning page redirects on confirmed threats.
- [M10]: DOMSignalExtractor analyzes structural elements only (action, type, style, src) with zero collection or transmission of inputs, values, or cookies.
- [M10]: WarningShroudManager mounts inside an isolated Shadow DOM container to prevent host page CSS from interfering with the alert.
- [M10]: Content script debounces dynamic SPA DOM mutations by 400ms to detect dynamically injected credential forms.

### Pending Todos

None yet.

### Blockers/Concerns

- Docker is not currently installed in the host's system PATH. Production container configurations are maintained in `docker/`, and local testing runs natively via Python venv and Node.js.

## Session Continuity

Last session: 2026-11-14 12:54  
Stopped at: Phase 10 complete and verified. Ready to plan and execute Phase 11 (Backend Integration and Cloud Enrichment).
