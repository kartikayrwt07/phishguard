# PhishGuard — Monorepo Architecture & Developer Guide

## Monorepo Layout

PhishGuard is structured as an integrated monorepo with strict isolation between client runtime, backend services, machine learning pipelines, and container infrastructure:

```text
phish/
├── backend/            # FastAPI Modular Monolith (Python 3.11+)
│   ├── app/
│   │   ├── core/       # Security, configuration, exceptions, structured logging
│   │   ├── database/   # SQLAlchemy 2.0 engine, sessions, base model
│   │   ├── models/     # Normalized PostgreSQL database ORM entities
│   │   ├── schemas/    # Pydantic v2 request/response validation schemas
│   │   ├── repositories/# Data access layer
│   │   ├── services/   # Business logic and coordination
│   │   ├── detection/  # 7-layer detection engine & explainable scoring
│   │   ├── intelligence/# Threat feed adapters (URLhaus, PhishTank, Safe Browsing)
│   │   ├── api/v1/     # Versioned REST controllers and auth routes
│   │   └── workers/    # Background feed synchronization and maintenance
│   ├── tests/          # Pytest automated test harness
│   └── requirements.txt
├── extension/          # Chrome Manifest V3 Browser Extension
│   ├── src/
│   │   ├── background/ # Service Worker, DeclarativeNetRequest manager, nav hooks
│   │   ├── content/    # Privacy-preserving DOM structural signal extractor
│   │   ├── popup/      # React popup UI (status, threat breakdown, allowlist)
│   │   ├── options/    # User settings and enterprise configuration UI
│   │   ├── warning/    # Standalone interstitial warning page
│   │   ├── detection/  # Local URL parser and heuristic scoring engine (<15ms)
│   │   └── shared/     # Typed contracts and communication protocols
│   ├── tests/          # Vitest unit and integration tests
│   └── manifest.json
├── dashboard/          # Administrative Console (React + Vite + Tailwind + TanStack Query)
│   ├── src/
│   │   ├── components/ # Accessible UI component library
│   │   ├── pages/      # 10 core administrative views (Scans, Feeds, Rules, etc.)
│   │   ├── services/   # API client and query hooks
│   │   └── store/      # Session and authentication state
│   └── tests/          # Vitest component and logic tests
├── ml/                 # Machine Learning Pipeline
│   ├── data/           # Dataset manifests and feature extraction definitions
│   ├── pipelines/      # Reproducible training, evaluation, and export scripts
│   ├── models/         # Versioned Joblib model artifacts
│   └── tests/          # Model metric validation tests
├── docker/             # Container orchestration and deployment packaging
│   ├── docker-compose.yml
│   ├── Dockerfile.backend
│   ├── Dockerfile.dashboard
│   └── nginx.conf
└── docs/               # Architecture, API specifications, and threat model
```

## Running Tests

### Backend (Pytest)
```bash
.\.venv\Scripts\pytest backend/tests -v
```

### Extension (Vitest)
```bash
npm --workspace=extension run test
```

### Dashboard (Vitest)
```bash
npm --workspace=dashboard run test
```

### Unified Run
```bash
npm run test:all
```

