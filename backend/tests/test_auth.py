"""
Automated Pytest suite testing Authentication, Token Lifecycle,
Security Headers, and Role-Based Access Control (RBAC).
"""
import pytest
import httpx
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database.base import Base
from app.database.session import get_db
from app.main import app
from app.models.user import UserRole


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
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    app.dependency_overrides[get_db] = override_get_db

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_health_check_and_security_headers(app_client: httpx.AsyncClient):
    """Test health check route and verify presence of security headers (SEC-02)."""
    response = await app_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "phishguard-backend"

    # Assert security headers
    headers = response.headers
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-content-type-options") == "nosniff"
    assert "default-src 'self'" in headers.get("content-security-policy", "")


@pytest.mark.asyncio
async def test_registration_and_duplicate_prevention(app_client: httpx.AsyncClient):
    """Test user registration with password complexity and duplicate email check."""
    # 1. Valid Registration
    reg_payload = {
        "email": "user1@example.com",
        "password": "SecurePassword123!",
        "full_name": "Test User One",
        "role": "user",
    }
    response = await app_client.post("/api/v1/auth/register", json=reg_payload)
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == "user1@example.com"
    assert data["user"]["role"] == "user"

    # 2. Duplicate Registration should return 409 Conflict
    dup_response = await app_client.post("/api/v1/auth/register", json=reg_payload)
    assert dup_response.status_code == 409
    dup_data = dup_response.json()
    assert dup_data["error"] == "DUPLICATE_RESOURCE"

    # 3. Short Password (< 8 chars) should fail validation (422)
    short_pwd_payload = {
        "email": "short@example.com",
        "password": "short",
    }
    short_resp = await app_client.post("/api/v1/auth/register", json=short_pwd_payload)
    assert short_resp.status_code == 422


@pytest.mark.asyncio
async def test_login_and_token_refresh(app_client: httpx.AsyncClient):
    """Test login flow, invalid password rejection, and token refresh."""
    # Register user
    reg_payload = {
        "email": "analyst@example.com",
        "password": "SuperSecretPassword123!",
        "full_name": "Security Analyst",
        "role": "analyst",
    }
    await app_client.post("/api/v1/auth/register", json=reg_payload)

    # Valid Login
    login_payload = {
        "email": "analyst@example.com",
        "password": "SuperSecretPassword123!",
    }
    login_resp = await app_client.post("/api/v1/auth/login", json=login_payload)
    assert login_resp.status_code == 200
    tokens = login_resp.json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Invalid Password Login
    bad_login = {
        "email": "analyst@example.com",
        "password": "WrongPassword999!",
    }
    bad_resp = await app_client.post("/api/v1/auth/login", json=bad_login)
    assert bad_resp.status_code == 401
    assert bad_resp.json()["error"] == "AUTHENTICATION_FAILED"

    # Token Refresh
    refresh_resp = await app_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_resp.status_code == 200
    refreshed = refresh_resp.json()
    assert "access_token" in refreshed

    # Invalid Refresh Token
    bad_refresh = await app_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid.jwt.token"},
    )
    assert bad_refresh.status_code == 401


@pytest.mark.asyncio
async def test_authenticated_profile_retrieval(app_client: httpx.AsyncClient):
    """Test GET /api/v1/auth/me with Bearer token authentication."""
    # Register user
    reg_payload = {
        "email": "profile.user@example.com",
        "password": "PasswordProfile123!",
        "full_name": "Profile Owner",
    }
    reg_resp = await app_client.post("/api/v1/auth/register", json=reg_payload)
    access_token = reg_resp.json()["access_token"]

    # 1. Unauthenticated Request -> 401
    unauth_resp = await app_client.get("/api/v1/auth/me")
    assert unauth_resp.status_code == 401

    # 2. Authenticated Request -> 200
    auth_resp = await app_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert auth_resp.status_code == 200
    profile = auth_resp.json()
    assert profile["email"] == "profile.user@example.com"
    assert profile["full_name"] == "Profile Owner"


@pytest.mark.asyncio
async def test_role_based_access_control_rbac(app_client: httpx.AsyncClient):
    """Test RBAC enforcement: standard user vs analyst vs admin."""
    # 1. Register a standard USER
    user_reg = await app_client.post(
        "/api/v1/auth/register",
        json={"email": "normal.user@example.com", "password": "UserPass123!", "role": "user"},
    )
    user_token = user_reg.json()["access_token"]

    # 2. Register an ANALYST
    analyst_reg = await app_client.post(
        "/api/v1/auth/register",
        json={"email": "sec.analyst@example.com", "password": "AnalystPass123!", "role": "analyst"},
    )
    analyst_token = analyst_reg.json()["access_token"]

    # 3. Register an ADMIN
    admin_reg = await app_client.post(
        "/api/v1/auth/register",
        json={"email": "sys.admin@example.com", "password": "AdminPass123!", "role": "admin"},
    )
    admin_token = admin_reg.json()["access_token"]

    # Test Admin Barrier (/api/v1/admin/verify-access)
    # - Standard user should be 403 Forbidden
    u_admin = await app_client.get(
        "/api/v1/admin/verify-access",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert u_admin.status_code == 403
    assert u_admin.json()["error"] == "PERMISSION_DENIED"

    # - Analyst should be 403 Forbidden
    a_admin = await app_client.get(
        "/api/v1/admin/verify-access",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert a_admin.status_code == 403

    # - Admin should be 200 OK
    adm_admin = await app_client.get(
        "/api/v1/admin/verify-access",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert adm_admin.status_code == 200

    # Test Analyst Barrier (/api/v1/analyst/verify-access)
    # - Standard user should be 403 Forbidden
    u_analyst = await app_client.get(
        "/api/v1/analyst/verify-access",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert u_analyst.status_code == 403

    # - Analyst should be 200 OK
    a_analyst = await app_client.get(
        "/api/v1/analyst/verify-access",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert a_analyst.status_code == 200

    # - Admin should also be 200 OK
    adm_analyst = await app_client.get(
        "/api/v1/analyst/verify-access",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert adm_analyst.status_code == 200
