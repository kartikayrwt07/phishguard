---
phase: PHISH-03-database-models-and-alembic-migrations
plan: "01"
subsystem: database
tags: [sqlalchemy, postgresql, sqlite, alembic, uuid, migrations]

requires:
  - phase: PHISH-02-monorepo-structure-and-development-infrastructure
    provides: Monorepo layout, Python virtual environment, and test harnesses
provides:
  - Base declarative class with GUID, JSONType, and timestamp mixins
  - 13 normalized SQLAlchemy 2.0 ORM models covering all PhishGuard domain entities
  - Alembic async migration configuration with baseline initial schema revision
  - Automated Pytest test suite covering model constraints, relationships, cascades, and enums
affects: [backend, detection, intelligence, api]

tech-stack:
  added: [sqlalchemy-2.0, alembic, greenlet, aiosqlite]
  patterns: [DeclarativeBase, UUIDPrimaryKeyMixin, TimestampMixin, cross-dialect JSONType, cascade deletions]

key-files:
  created:
    - backend/app/database/base.py
    - backend/app/database/session.py
    - backend/app/core/config.py
    - backend/app/models/user.py
    - backend/app/models/device.py
    - backend/app/models/scan.py
    - backend/app/models/threat.py
    - backend/app/models/rule.py
    - backend/app/models/ml.py
    - backend/app/models/report.py
    - backend/app/models/allowlist.py
    - backend/app/models/audit.py
    - backend/app/models/setting.py
    - backend/alembic.ini
    - backend/alembic/env.py
    - backend/alembic/versions/794b1b85602e_initial_phishguard_schema.py
    - backend/tests/test_models.py

key-decisions:
  - "Used platform-independent GUID TypeDecorator mapping to native PG UUID in Postgres and String(36) in SQLite"
  - "Used dialect-aware JSONType mapping to JSONB in Postgres and standard JSON in SQLite"
  - "Configured cascade delete on Scan -> ScanEvidence and ThreatSource -> FeedSyncLog"
  - "Alembic configured for async migrations using SQLAlchemy async engine and batch alter mode for SQLite"

patterns-established:
  - "All primary keys use UUID4"
  - "All timestamps store UTC timezone-aware datetimes"
  - "Enums defined with native_enum=False for maximum database portability"

requirements-completed:
  - API-05
  - API-06

duration: 25min
completed: 2026-11-14
---

# Phase 03: Database Models and Alembic Migrations Summary

**Implemented 13 normalized SQLAlchemy 2.0 database models with UUID primary keys, UTC timestamps, JSONB/JSON abstractions, and async Alembic migrations.**

## Accomplishments
- Implemented `backend/app/database/base.py` with `DeclarativeBase`, `GUID` type decorator, `JSONType` dialect-aware type, `UUIDPrimaryKeyMixin`, and `TimestampMixin`.
- Created 13 domain models across 10 modular files:
  1. `User` (email, Argon2 hash, full_name, UserRole enum: admin/analyst/user, is_active)
  2. `ExtensionDevice` (device_identifier, extension_version, browser_type, last_seen_at, is_revoked)
  3. `Scan` (url, normalized_url, domain, ScanVerdict enum: SAFE/SUSPICIOUS/PHISHING/UNKNOWN, risk_score, confidence, engine_version, scan_duration_ms)
  4. `ScanEvidence` (layer_name, rule_code, score_contribution, confidence, evidence_data JSONB, cascade delete)
  5. `ThreatSource` (name, feed_url, is_enabled, sync_interval_minutes, health_status)
  6. `ThreatIndicator` (IndicatorType enum, indicator_value, threat_type, ThreatSeverity enum, metadata_payload JSONB)
  7. `FeedSyncLog` (SyncStatus enum, records_added, records_updated, error_message, duration_seconds)
  8. `DetectionRule` (rule_code, name, description, layer, weight, threshold, is_enabled, parameters JSONB)
  9. `MLModel` (model_name, version, algorithm, metrics JSONB, artifact_path, is_active, deployed_at)
  10. `UserReport` (ReportType enum, comments, ReportStatus enum, reviewer relation, resolution_notes)
  11. `AllowlistEntry` (PatternType enum, pattern, reason, is_enterprise, expires_at, is_active)
  12. `AuditLog` (actor_id, actor_type, action, target_type, target_id, details JSONB, ip_address, user_agent)
  13. `SystemSetting` (key, value JSONB, description, modifier relation)
- Initialized Alembic with async engine support and generated baseline migration `794b1b85602e_initial_phishguard_schema.py`.
- Verified migration roundtrip (`alembic upgrade head` and `alembic downgrade base`).
- Built automated test suite `backend/tests/test_models.py` verifying all models, relationships, cascades, and enums. All 7 tests pass with 0 warnings.

