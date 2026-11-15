"""
FastAPI dependencies for authentication, authorization (RBAC), and database sessions.
"""
import uuid
from typing import Callable, List, Optional
import jwt
from fastapi import Depends, Header, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, PermissionDeniedError
from app.core.security import decode_token
from app.database.session import get_db
from app.models.user import User, UserRole
from app.repositories.user_repo import UserRepository

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    session: AsyncSession = Depends(get_db),
) -> User:
    """Validate Bearer access token and return the authenticated User entity."""
    if not credentials or not credentials.credentials:
        raise AuthenticationError("Authentication token is required")

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except (jwt.PyJWTError, Exception):
        raise AuthenticationError("Invalid authentication token")

    if payload.get("type") != "access":
        raise AuthenticationError("Token is not an access token")

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise AuthenticationError("Malformed token subject")

    try:
        user_uuid = uuid.UUID(user_id_str)
    except ValueError:
        raise AuthenticationError("Invalid user identifier in token")

    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_uuid)
    if not user or not user.is_active:
        raise AuthenticationError("User not found or account is inactive")

    return user


def require_role(allowed_roles: List[UserRole]) -> Callable:
    """Dependency factory enforcing server-side Role-Based Access Control (RBAC)."""

    async def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise PermissionDeniedError(
                f"Action requires one of roles {[r.value for r in allowed_roles]}, "
                f"user has role '{current_user.role.value}'"
            )
        return current_user

    return role_checker


# Convenient role dependencies
get_current_admin = require_role([UserRole.ADMIN])
get_current_analyst_or_admin = require_role([UserRole.ADMIN, UserRole.ANALYST])
