"""
Custom exception hierarchy and standardized API error formatting.
"""
from typing import Any, Dict, Optional
from fastapi import HTTPException, status


class PhishGuardException(HTTPException):
    """Base exception class for all PhishGuard operational errors."""

    def __init__(
        self,
        status_code: int,
        detail: str,
        error_code: str = "INTERNAL_ERROR",
        extra: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(status_code=status_code, detail=detail)
        self.error_code = error_code
        self.extra = extra or {}


class AuthenticationError(PhishGuardException):
    """Raised when authentication credentials are invalid or missing."""

    def __init__(self, detail: str = "Could not validate credentials"):
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            error_code="AUTHENTICATION_FAILED",
        )


class PermissionDeniedError(PhishGuardException):
    """Raised when an authenticated user lacks required privileges."""

    def __init__(self, detail: str = "Insufficient permissions to perform this action"):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            error_code="PERMISSION_DENIED",
        )


class ResourceNotFoundError(PhishGuardException):
    """Raised when a requested resource is not found."""

    def __init__(self, resource: str, identifier: Any):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource} with identifier '{identifier}' was not found",
            error_code="RESOURCE_NOT_FOUND",
        )


class DuplicateResourceError(PhishGuardException):
    """Raised when a resource uniqueness constraint is violated."""

    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            error_code="DUPLICATE_RESOURCE",
        )

