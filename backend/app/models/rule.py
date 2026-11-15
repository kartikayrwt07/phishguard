"""
DetectionRule entity for configurable heuristic rules and thresholds.
"""
import uuid
from typing import Any, Dict, Optional
from sqlalchemy import Boolean, Float, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class DetectionRule(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "detection_rules"

    rule_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    layer: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    weight: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    threshold: Mapped[float] = mapped_column(Float, default=0.5, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    parameters: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    created_by: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    author: Mapped[Optional["User"]] = relationship("User")

