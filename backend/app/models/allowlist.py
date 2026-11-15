"""
AllowlistEntry entity for trusted domain/URL exceptions.
"""
import uuid
from datetime import datetime
from enum import Enum
from typing import Optional
from sqlalchemy import Boolean, DateTime, Enum as SQLEnum, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, TimestampMixin, UUIDPrimaryKeyMixin


class PatternType(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    REGEX = "regex"


class AllowlistEntry(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "allowlist_entries"

    pattern_type: Mapped[PatternType] = mapped_column(
        SQLEnum(PatternType, name="pattern_type_enum", native_enum=False),
        default=PatternType.DOMAIN,
        nullable=False,
        index=True,
    )
    pattern: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    is_enterprise: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    author: Mapped[Optional["User"]] = relationship("User")

