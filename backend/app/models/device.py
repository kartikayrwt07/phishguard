"""
ExtensionDevice entity representing a registered browser extension instance.
"""
import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class ExtensionDevice(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "extension_devices"

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    device_identifier: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    extension_version: Mapped[str] = mapped_column(String(32), nullable=False)
    browser_type: Mapped[str] = mapped_column(String(64), default="chrome", nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="devices")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="device")

