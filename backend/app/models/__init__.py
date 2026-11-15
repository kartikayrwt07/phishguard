"""
Export of all SQLAlchemy 2.0 ORM models for PhishGuard.
"""
from app.models.user import User, UserRole
from app.models.device import ExtensionDevice
from app.models.scan import Scan, ScanEvidence, ScanVerdict
from app.models.threat import (
    FeedSyncLog,
    IndicatorType,
    SyncStatus,
    ThreatIndicator,
    ThreatSeverity,
    ThreatSource,
)
from app.models.rule import DetectionRule
from app.models.ml import MLModel
from app.models.report import ReportStatus, ReportType, UserReport
from app.models.allowlist import AllowlistEntry, PatternType
from app.models.audit import AuditLog
from app.models.setting import SystemSetting

__all__ = [
    # User & Device
    "User",
    "UserRole",
    "ExtensionDevice",
    # Scan & Evidence
    "Scan",
    "ScanEvidence",
    "ScanVerdict",
    # Threat Intelligence
    "ThreatSource",
    "ThreatIndicator",
    "FeedSyncLog",
    "IndicatorType",
    "ThreatSeverity",
    "SyncStatus",
    # Rules & ML
    "DetectionRule",
    "MLModel",
    # Reports & Exceptions
    "UserReport",
    "ReportType",
    "ReportStatus",
    "AllowlistEntry",
    "PatternType",
    # Audit & Settings
    "AuditLog",
    "SystemSetting",
]

