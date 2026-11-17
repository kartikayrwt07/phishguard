"""
Scan API Endpoints.
Provides REST endpoints for initiating scans, querying scan history, and inspecting evidence.
"""
from typing import Optional
import uuid
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_optional_user
from app.database.session import get_db
from app.models.user import User
from app.schemas.scan import (
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
)
from app.services.scan_service import ScanService

router = APIRouter(prefix="/scan", tags=["Scanning & Detection"])


@router.post(
    "",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Scan and analyze a target URL",
)
async def scan_url(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
) -> ScanResponse:
    """
    Execute multi-layer phishing and risk detection for a URL.
    Optionally enriches with client DOM signals, threat feeds, and persists audit evidence.
    """
    service = ScanService(db)
    user_id = current_user.id if current_user else None
    return await service.scan_url(request, user_id=user_id)


@router.get(
    "/history",
    response_model=ScanHistoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve scan history",
)
async def get_scan_history(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
) -> ScanHistoryResponse:
    """Retrieve historical scans with pagination."""
    service = ScanService(db)
    user_id = current_user.id if current_user else None
    return await service.get_history(user_id=user_id, limit=limit, offset=offset)


@router.get(
    "/{scan_id}",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Get scan by ID",
)
async def get_scan_by_id(
    scan_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
) -> ScanResponse:
    """Retrieve details and itemized evidence for a specific scan."""
    service = ScanService(db)
    scan = await service.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan with ID '{scan_id}' not found.",
        )
    return scan
