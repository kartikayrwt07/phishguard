"""
UserReport entity for false-positive and false-negative triage.
"""
import uuid
from enum import Enum
from typing import Optional
from sqlalchemy import Enum as SQLEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, TimestampMixin, UUIDPrimaryKeyMixin


class ReportType(str, Enum):
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"


class ReportStatus(str, Enum):
    PENDING = "pending"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"


class UserReport(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "user_reports"

    scan_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("scans.id", ondelete="SET NULL"), nullable=True, index=True)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    reported_url: Mapped[str] = mapped_column(Text, nullable=False)
    report_type: Mapped[ReportType] = mapped_column(
        SQLEnum(ReportType, name="report_type_enum", native_enum=False),
        nullable=False,
        index=True,
    )
    comments: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[ReportStatus] = mapped_column(
        SQLEnum(ReportStatus, name="report_status_enum", native_enum=False),
        default=ReportStatus.PENDING,
        nullable=False,
        index=True,
    )
    reviewed_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolution_notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped[Optional["Scan"]] = relationship("Scan", back_populates="reports")
    user: Mapped[Optional["User"]] = relationship("User", back_populates="reports", foreign_keys=[user_id])
    reviewer: Mapped[Optional["User"]] = relationship("User", back_populates="reviewed_reports", foreign_keys=[reviewed_by])

