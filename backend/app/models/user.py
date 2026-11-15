"""
User entity and UserRole enum.
"""
from enum import Enum
from typing import List, Optional
from sqlalchemy import Boolean, Enum as SQLEnum, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    USER = "user"


class User(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole, name="user_role_enum", native_enum=False),
        default=UserRole.USER,
        nullable=False,
        index=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    devices: Mapped[List["ExtensionDevice"]] = relationship("ExtensionDevice", back_populates="user", cascade="all, delete-orphan")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user")
    reports: Mapped[List["UserReport"]] = relationship("UserReport", back_populates="user", foreign_keys="UserReport.user_id")
    reviewed_reports: Mapped[List["UserReport"]] = relationship("UserReport", back_populates="reviewer", foreign_keys="UserReport.reviewed_by")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="actor")

