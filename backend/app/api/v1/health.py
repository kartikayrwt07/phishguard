"""
System health and operational status endpoints.
"""
from typing import Dict
from fastapi import APIRouter, Depends, status

from app.api.deps import get_current_admin, get_current_analyst_or_admin
from app.models.user import User

router = APIRouter(tags=["Health & Status"])


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Service Health Check",
)
async def health_check() -> Dict[str, str]:
    """Return healthy status code for monitoring and container healthchecks."""
    return {
        "status": "healthy",
        "service": "phishguard-backend",
        "version": "1.0.0",
    }


@router.get(
    "/admin/verify-access",
    status_code=status.HTTP_200_OK,
    summary="Verify Admin RBAC Barrier",
)
async def admin_access_check(
    admin_user: User = Depends(get_current_admin),
) -> Dict[str, str]:
    """Test endpoint proving that only ADMIN role can access this resource."""
    return {"message": "Admin authorization verified", "user_id": str(admin_user.id)}


@router.get(
    "/analyst/verify-access",
    status_code=status.HTTP_200_OK,
    summary="Verify Analyst/Admin RBAC Barrier",
)
async def analyst_access_check(
    analyst_user: User = Depends(get_current_analyst_or_admin),
) -> Dict[str, str]:
    """Test endpoint proving that ANALYST or ADMIN roles can access this resource."""
    return {"message": "Analyst authorization verified", "role": analyst_user.role.value}
