"""
Authentication service orchestrating registration, credential verification, and token issuance.
"""
from datetime import timedelta
import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import AuthenticationError, DuplicateResourceError
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.models.user import User, UserRole
from app.repositories.user_repo import UserRepository
from app.schemas.auth import (
    LoginRequest,
    RegisterRequest,
    TokenRefreshResponse,
    TokenResponse,
)
from app.schemas.user import UserResponse


class AuthService:
    """Service layer managing user authentication and JWT lifecycle."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.user_repo = UserRepository(session)

    async def register(self, request: RegisterRequest) -> TokenResponse:
        """Register a new user account with Argon2id password hash."""
        existing = await self.user_repo.get_by_email(request.email)
        if existing:
            raise DuplicateResourceError(f"A user with email '{request.email}' already exists")

        user = User(
            email=request.email.lower().strip(),
            password_hash=hash_password(request.password),
            full_name=request.full_name,
            role=request.role or UserRole.USER,
            is_active=True,
        )
        created_user = await self.user_repo.create(user)

        # Issue tokens
        access_token = create_access_token(
            subject=str(created_user.id),
            role=created_user.role.value,
        )
        refresh_token = create_refresh_token(subject=str(created_user.id))

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(created_user),
        )

    async def login(self, request: LoginRequest) -> TokenResponse:
        """Authenticate user credentials and issue token pair."""
        user = await self.user_repo.get_by_email(request.email)
        if not user or not verify_password(request.password, user.password_hash):
            raise AuthenticationError("Invalid email or password")

        if not user.is_active:
            raise AuthenticationError("Account is inactive")

        access_token = create_access_token(
            subject=str(user.id),
            role=user.role.value,
        )
        refresh_token = create_refresh_token(subject=str(user.id))

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            user=UserResponse.model_validate(user),
        )

    async def refresh_access_token(self, refresh_token: str) -> TokenRefreshResponse:
        """Validate a refresh token and issue a new access token."""
        try:
            payload = decode_token(refresh_token)
        except (jwt.PyJWTError, Exception):
            raise AuthenticationError("Invalid or expired refresh token")

        if payload.get("type") != "refresh":
            raise AuthenticationError("Token is not a valid refresh token")

        user_id_str = payload.get("sub")
        if not user_id_str:
            raise AuthenticationError("Malformed token subject")

        import uuid
        try:
            user_uuid = uuid.UUID(user_id_str)
        except ValueError:
            raise AuthenticationError("Malformed user identifier in token")

        user = await self.user_repo.get_by_id(user_uuid)
        if not user or not user.is_active:
            raise AuthenticationError("User not found or account inactive")

        access_token = create_access_token(
            subject=str(user.id),
            role=user.role.value,
        )

        return TokenRefreshResponse(
            access_token=access_token,
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

