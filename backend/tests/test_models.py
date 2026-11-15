"""
Automated Pytest suite testing all 13 SQLAlchemy 2.0 ORM models,
UUID primary keys, UTC timestamps, relationships, and cascade behaviors.
"""
import uuid
from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.database.base import Base
from app.models import (
    AllowlistEntry,
    AuditLog,
    DetectionRule,
    ExtensionDevice,
    FeedSyncLog,
    IndicatorType,
    MLModel,
    PatternType,
    ReportStatus,
    ReportType,
    Scan,
    ScanEvidence,
    ScanVerdict,
    SyncStatus,
    SystemSetting,
    ThreatIndicator,
    ThreatSeverity,
    ThreatSource,
    User,
    UserReport,
    UserRole,
)


@pytest.fixture
async def test_session():
    """Create an isolated in-memory SQLite database session for unit tests."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await test_engine.dispose()


@pytest.mark.asyncio
async def test_user_and_device_relationship(test_session: AsyncSession):
    """Test User creation and ExtensionDevice relationship."""
    user = User(
        email="security.analyst@phishguard.internal",
        password_hash="argon2id_mock_hash_for_testing",
        full_name="Alice Analyst",
        role=UserRole.ANALYST,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    assert isinstance(user.id, uuid.UUID)
    assert user.role == UserRole.ANALYST
    assert user.is_active is True
    assert user.created_at is not None

    device = ExtensionDevice(
        user_id=user.id,
        device_identifier="device-uuid-token-xyz-123",
        extension_version="1.0.0",
        browser_type="chrome",
    )
    test_session.add(device)
    await test_session.commit()
    await test_session.refresh(device)

    assert isinstance(device.id, uuid.UUID)
    assert device.user_id == user.id
    assert device.browser_type == "chrome"


@pytest.mark.asyncio
async def test_scan_and_evidence_cascade(test_session: AsyncSession):
    """Test Scan and ScanEvidence cascade delete behavior."""
    scan = Scan(
        url="https://paypa1-secure-login.com/login.php",
        normalized_url="http://paypa1-secure-login.com/login.php",
        domain="paypa1-secure-login.com",
        verdict=ScanVerdict.PHISHING,
        risk_score=94.5,
        confidence=0.98,
        engine_version="1.0.0",
        scan_duration_ms=45,
    )
    test_session.add(scan)
    await test_session.commit()
    await test_session.refresh(scan)

    evidence_1 = ScanEvidence(
        scan_id=scan.id,
        layer_name="brand_impersonation",
        rule_code="BRAND_HOMOGLYPH_MATCH",
        score_contribution=40.0,
        confidence=0.95,
        evidence_data={"impersonated_brand": "PayPal", "levenshtein_distance": 1},
    )
    evidence_2 = ScanEvidence(
        scan_id=scan.id,
        layer_name="url_analysis",
        rule_code="SUSPICIOUS_KEYWORDS",
        score_contribution=25.0,
        confidence=0.90,
        evidence_data={"keywords_detected": ["login", "secure"]},
    )
    test_session.add_all([evidence_1, evidence_2])
    await test_session.commit()

    # Verify evidence stored
    result = await test_session.execute(
        select(ScanEvidence).where(ScanEvidence.scan_id == scan.id)
    )
    evidence_list = result.scalars().all()
    assert len(evidence_list) == 2

    # Delete scan and verify cascade delete of evidence
    await test_session.delete(scan)
    await test_session.commit()

    ev_check = await test_session.execute(
        select(ScanEvidence).where(ScanEvidence.scan_id == scan.id)
    )
    assert len(ev_check.scalars().all()) == 0


@pytest.mark.asyncio
async def test_threat_source_and_indicators(test_session: AsyncSession):
    """Test ThreatSource, ThreatIndicator, and FeedSyncLog persistence."""
    source = ThreatSource(
        name="urlhaus",
        feed_url="https://urlhaus-api.abuse.ch/v1/",
        sync_interval_minutes=30,
        health_status="healthy",
    )
    test_session.add(source)
    await test_session.commit()
    await test_session.refresh(source)

    indicator = ThreatIndicator(
        indicator_type=IndicatorType.DOMAIN,
        indicator_value="malicious-phish-domain.xyz",
        threat_type="credential_stealer",
        severity=ThreatSeverity.CRITICAL,
        source_id=source.id,
        metadata_payload={"tags": ["banking", "phish"]},
    )
    sync_log = FeedSyncLog(
        source_id=source.id,
        status=SyncStatus.SUCCESS,
        records_added=1500,
        records_updated=20,
        duration_seconds=3.4,
    )
    test_session.add_all([indicator, sync_log])
    await test_session.commit()

    assert indicator.indicator_type == IndicatorType.DOMAIN
    assert indicator.severity == ThreatSeverity.CRITICAL
    assert indicator.metadata_payload["tags"] == ["banking", "phish"]
    assert sync_log.status == SyncStatus.SUCCESS


@pytest.mark.asyncio
async def test_detection_rule_and_ml_model(test_session: AsyncSession):
    """Test DetectionRule and MLModel entities."""
    rule = DetectionRule(
        rule_code="RULE_ENTROPY_HIGH",
        name="High Hostname Entropy",
        description="Flags domain names with Shannon entropy above 4.2",
        layer="url_analysis",
        weight=1.5,
        threshold=4.2,
        parameters={"entropy_algorithm": "shannon", "min_length": 12},
    )
    ml_model = MLModel(
        model_name="PhishGuard_RandomForest",
        version="v1.0.0",
        algorithm="RandomForestClassifier",
        metrics={"f1_score": 0.982, "precision": 0.985, "recall": 0.979},
        artifact_path="ml/models/phishguard_rf_v1.joblib",
        is_active=True,
    )
    test_session.add_all([rule, ml_model])
    await test_session.commit()

    assert rule.weight == 1.5
    assert rule.parameters["min_length"] == 12
    assert ml_model.metrics["f1_score"] == 0.982
    assert ml_model.is_active is True


@pytest.mark.asyncio
async def test_user_report_and_allowlist(test_session: AsyncSession):
    """Test UserReport, AllowlistEntry, AuditLog, and SystemSetting entities."""
    user = User(
        email="reporter@example.com",
        password_hash="dummy_hash",
        role=UserRole.USER,
    )
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)

    report = UserReport(
        user_id=user.id,
        reported_url="https://legitimate-corporate-portal.com",
        report_type=ReportType.FALSE_POSITIVE,
        comments="This is an internal portal incorrectly flagged.",
        status=ReportStatus.PENDING,
    )
    allowlist = AllowlistEntry(
        pattern_type=PatternType.DOMAIN,
        pattern="legitimate-corporate-portal.com",
        reason="Corporate intranet exception",
        created_by=user.id,
        is_enterprise=True,
    )
    audit = AuditLog(
        actor_id=user.id,
        action="ALLOWLIST_CREATE",
        target_type="allowlist_entry",
        details={"pattern": "legitimate-corporate-portal.com"},
        ip_address="192.168.1.50",
    )
    setting = SystemSetting(
        key="detection.min_phishing_score",
        value={"threshold": 70.0, "strict_mode": True},
        description="Threshold above which a URL is classified as PHISHING",
    )
    test_session.add_all([report, allowlist, audit, setting])
    await test_session.commit()

    assert report.report_type == ReportType.FALSE_POSITIVE
    assert allowlist.is_enterprise is True
    assert audit.action == "ALLOWLIST_CREATE"
    assert setting.value["threshold"] == 70.0

