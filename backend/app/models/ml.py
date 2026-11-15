"""
MLModel entity tracking machine learning model versions, metrics, and deployment state.
"""
from datetime import datetime
from typing import Any, Dict, Optional
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class MLModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "ml_models"

    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    metrics: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)
    artifact_path: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    deployed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

