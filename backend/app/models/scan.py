"""
Scan and ScanEvidence entities representing URL scan histories and evidence.
"""
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from sqlalchemy import Enum as SQLEnum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, GUID, JSONType, TimestampMixin, UUIDPrimaryKeyMixin


class ScanVerdict(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    PHISHING = "PHISHING"
    UNKNOWN = "UNKNOWN"


class Scan(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scans"

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    device_id: Mapped[Optional[uuid.UUID]] = mapped_column(GUID, ForeignKey("extension_devices.id", ondelete="SET NULL"), nullable=True, index=True)
    
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, index=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    
    verdict: Mapped[ScanVerdict] = mapped_column(
        SQLEnum(ScanVerdict, name="scan_verdict_enum", native_enum=False),
        default=ScanVerdict.UNKNOWN,
        nullable=False,
        index=True,
    )
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    engine_version: Mapped[str] = mapped_column(String(32), default="1.0.0", nullable=False)
    scan_duration_ms: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="scans")
    device: Mapped[Optional["ExtensionDevice"]] = relationship("ExtensionDevice", back_populates="scans")
    evidence: Mapped[List["ScanEvidence"]] = relationship(
        "ScanEvidence",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
    reports: Mapped[List["UserReport"]] = relationship("UserReport", back_populates="scan")


class ScanEvidence(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "scan_evidence"

    scan_id: Mapped[uuid.UUID] = mapped_column(GUID, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    layer_name: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    rule_code: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    score_contribution: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    evidence_data: Mapped[Dict[str, Any]] = mapped_column(JSONType, default=dict, nullable=False)

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="evidence")

