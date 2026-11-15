"""
Threat intelligence entities: ThreatSource, ThreatIndicator, and FeedSyncLog.
"""
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from sqlalchemy import Boolean, DateTime, Enum as SQLEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, JSONType, TimestampMixin, UUIDPrimaryKeyMixin, utc_now


class IndicatorType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    URL = "url"
    URL_HASH = "url_hash"


class ThreatSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SyncStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class ThreatSource(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "threat_sources"

    name: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    feed_url: Mapped[str] = mapped_column(String(512), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_synced_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    health_status: Mapped[str] = mapped_column(String(32), default="healthy", nullable=False)

    # Relationships
    indicators: Mapped[List["ThreatIndicator"]] = relationship("ThreatIndicator", back_populates="source")
    sync_logs: Mapped[List["FeedSyncLog"]] = relationship("FeedSyncLog", back_populates="source", cascade="all, delete-orphan")


class ThreatIndicator(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "threat_indicators"

    indicator_type: Mapped[IndicatorType] = mapped_column(
        SQLEnum(IndicatorType, name="indicator_type_enum", native_enum=False),
        nullable=False,
        index=True,
    )
    indicator_value: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    threat_type: Mapped[str] = mapped_column(String(64), default="phishing", nullable=False, index=True)
    severity: Mapped[ThreatSeverity] = mapped_column(
        SQLEnum(ThreatSeverity, name="threat_severity_enum", native_enum=False),
        default=ThreatSeverity.HIGH,
        nullable=False,
    )
    source_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("threat_sources.id", ondelete="SET NULL"), nullable=True, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    metadata_payload: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    # Relationships
    source: Mapped[Optional["ThreatSource"]] = relationship("ThreatSource", back_populates="indicators")


class FeedSyncLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "feed_sync_logs"

    source_id: Mapped[uuid.UUID] = mapped_column(GUID, ForeignKey("threat_sources.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[SyncStatus] = mapped_column(
        SQLEnum(SyncStatus, name="sync_status_enum", native_enum=False),
        default=SyncStatus.PENDING,
        nullable=False,
        index=True,
    )
    records_added: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    records_updated: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    source: Mapped["ThreatSource"] = relationship("ThreatSource", back_populates="sync_logs")

