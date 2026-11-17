"""
Pydantic Schemas for URL Scanning and Risk Analysis.
"""
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class DOMSignalsPayload(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    has_password_field: bool = False
    has_login_form: bool = False
    form_action_origin_mismatch: bool = False
    form_action_is_ip: bool = False
    form_action_target: Optional[str] = None
    hidden_iframes_count: int = 0
    external_resources_ratio: float = 0.0


class ScanRequest(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to scan and analyze")
    device_id: Optional[str] = Field(None, description="Client installation UUID if submitted from extension")
    dom_signals: Optional[DOMSignalsPayload] = Field(None, description="Structural DOM signals from content script")


class EvidenceItemSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rule_name: str
    layer: str
    score_impact: float
    description: str
    confidence: float
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ScanResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    scan_id: str
    url: str
    normalized_url: str
    domain: str
    verdict: str
    risk_score: float
    confidence: float
    evidence: List[EvidenceItemSchema]
    threat_sources: List[str] = Field(default_factory=list)
    scan_duration_ms: int
    scanned_at: str
    engine_version: str


class ScanHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total: int
    scans: List[ScanResponse]
