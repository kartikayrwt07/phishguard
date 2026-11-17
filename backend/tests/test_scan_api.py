"""
Automated tests for Backend Scan API Endpoints (/api/v1/scan).
"""
import pytest
import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database.base import Base
from app.database.session import get_db
from app.main import app


@pytest.fixture
async def app_client():
    """Create a test client with an isolated in-memory database."""
    test_engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        connect_args={"check_same_thread": False},
    )

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    test_session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async def override_get_db():
        async with test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_scan_api_clean_url(app_client):
    """Verify scanning a clean legitimate URL returns SAFE and persists in DB."""
    payload = {
        "url": "https://www.google.com",
    }
    resp = await app_client.post("/api/v1/scan", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "SAFE"
    assert data["risk_score"] == 0
    assert data["scan_id"] is not None
    assert data["domain"] == "www.google.com"


@pytest.mark.asyncio
async def test_scan_api_phishing_url(app_client):
    """Verify scanning a compound lookalike phishing URL returns PHISHING with evidence."""
    payload = {
        "url": "http://paypa1-account-security.xyz/login.php",
    }
    resp = await app_client.post("/api/v1/scan", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert data["verdict"] == "PHISHING"
    assert data["risk_score"] >= 70
    assert len(data["evidence"]) >= 1
    assert any(e["rule_name"].startswith("BRAND_") for e in data["evidence"])


@pytest.mark.asyncio
async def test_scan_api_with_dom_signals(app_client):
    """Verify DOM structural indicators are aggregated into the risk score."""
    payload = {
        "url": "http://suspicious-site.example.com/portal",
        "dom_signals": {
            "has_password_field": True,
            "has_login_form": True,
            "form_action_origin_mismatch": True,
            "form_action_is_ip": False,
            "form_action_target": "http://evil-collector.xyz",
            "hidden_iframes_count": 4,
            "external_resources_ratio": 0.8,
        },
    }
    resp = await app_client.post("/api/v1/scan", json=payload)

    assert resp.status_code == 200
    data = resp.json()
    assert data["risk_score"] >= 40
    rules = [e["rule_name"] for e in data["evidence"]]
    assert "DOM_PASSWORD_CROSS_ORIGIN" in rules
    assert "DOM_EXCESSIVE_HIDDEN_IFRAMES" in rules


@pytest.mark.asyncio
async def test_scan_api_lookup_by_id_and_history(app_client):
    """Verify scan retrieval by scan_id and history pagination."""
    # Create scan
    create_resp = await app_client.post(
        "/api/v1/scan",
        json={"url": "https://example-test.com/inspect"},
    )
    assert create_resp.status_code == 200
    scan_id = create_resp.json()["scan_id"]

    # Fetch by ID
    get_resp = await app_client.get(f"/api/v1/scan/{scan_id}")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["scan_id"] == scan_id
    assert get_data["url"] == "https://example-test.com/inspect"

    # Fetch history
    hist_resp = await app_client.get("/api/v1/scan/history?limit=10")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total"] >= 1
    assert any(s["scan_id"] == scan_id for s in hist_data["scans"])
