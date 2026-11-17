"""
Scan Orchestration Service.
Coordinates URL parsing, external threat intelligence lookups, DOM signal evaluation,
risk scoring via RiskEngine, and database persistence.
"""
from datetime import datetime, timezone
import time
from typing import List, Optional
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.detection.dom_evaluator import DOMSignals
from app.detection.scoring import RiskEngine
from app.detection.url_parser import URLNormalizer
from app.intelligence.service import ThreatIntelligenceService
from app.models.allowlist import AllowlistEntry
from app.models.scan import Scan, ScanEvidence, ScanVerdict
from app.schemas.scan import (
    EvidenceItemSchema,
    ScanHistoryResponse,
    ScanRequest,
    ScanResponse,
)


class ScanService:
    def __init__(
        self,
        db: AsyncSession,
        threat_service: Optional[ThreatIntelligenceService] = None,
    ):
        self.db = db
        self.threat_service = threat_service or ThreatIntelligenceService()

    async def scan_url(
        self,
        request: ScanRequest,
        user_id: Optional[uuid.UUID] = None,
    ) -> ScanResponse:
        """
        Orchestrate full multi-layer detection and persist scan evidence.
        """
        start_time = time.monotonic()
        parsed = URLNormalizer.parse(request.url)

        # 1. Check Allowlist in Database
        is_allowlisted = False
        allowlist_reason: Optional[str] = None

        if parsed.host:
            allow_query = select(AllowlistEntry).where(
                (AllowlistEntry.pattern == parsed.host) | (AllowlistEntry.pattern == parsed.registered_domain),
                AllowlistEntry.is_active == True,
            )
            allow_result = await self.db.execute(allow_query)
            matched_allow = allow_result.scalars().first()
            if matched_allow:
                is_allowlisted = True
                allowlist_reason = matched_allow.reason or "Domain is on organizational allowlist."

        # 2. Check Threat Intelligence Feeds (if not allowlisted)
        threat_feed_hit = False
        threat_feed_source: Optional[str] = None
        confirmed_sources: List[str] = []

        if not is_allowlisted:
            enrichment = await self.threat_service.check_url(parsed.normalized_url, timeout_budget_seconds=1.5)
            if enrichment.is_threat:
                threat_feed_hit = True
                confirmed_sources = enrichment.confirmed_sources
                threat_feed_source = (
                    f"External feeds ({', '.join(confirmed_sources)}): {enrichment.evidence_summary}"
                )

        # 3. Convert DOM Signals if provided
        dom_signals: Optional[DOMSignals] = None
        if request.dom_signals:
            form_action_hosts = []
            if request.dom_signals.form_action_target:
                form_action_hosts.append(request.dom_signals.form_action_target)

            dom_signals = DOMSignals(
                page_url=parsed.raw_url,
                has_password_field=request.dom_signals.has_password_field,
                has_login_form=request.dom_signals.has_login_form,
                form_action_hosts=form_action_hosts,
                has_ip_form_action=request.dom_signals.form_action_is_ip,
                has_cross_origin_form=request.dom_signals.form_action_origin_mismatch,
                hidden_iframe_count=request.dom_signals.hidden_iframes_count,
            )

        # 4. Evaluate Multi-Layer Risk Engine
        risk_report = RiskEngine.evaluate(
            url=parsed.raw_url,
            dom_signals=dom_signals,
            is_threat_feed_match=threat_feed_hit,
            threat_feed_source=threat_feed_source,
            is_allowlisted=is_allowlisted,
            allowlist_reason=allowlist_reason,
        )

        elapsed_ms = int((time.monotonic() - start_time) * 1000)

        # 5. Persist Scan and Evidence to Database
        device_uuid: Optional[uuid.UUID] = None
        if request.device_id:
            try:
                device_uuid = uuid.UUID(request.device_id)
            except ValueError:
                device_uuid = None

        scan = Scan(
            user_id=user_id,
            device_id=device_uuid,
            url=parsed.raw_url,
            normalized_url=parsed.normalized_url,
            domain=parsed.host,
            verdict=risk_report.verdict,
            risk_score=risk_report.risk_score,
            confidence=risk_report.confidence,
            engine_version=risk_report.engine_version,
            scan_duration_ms=elapsed_ms,
        )
        self.db.add(scan)
        await self.db.flush()

        # Add Evidence Records
        evidence_schemas: List[EvidenceItemSchema] = []
        for item in risk_report.evidence:
            evidence_rec = ScanEvidence(
                scan_id=scan.id,
                layer_name=item.layer_name,
                rule_code=item.rule_code,
                score_contribution=item.score_contribution,
                confidence=item.confidence,
                evidence_data={"description": item.description, **item.details},
            )
            self.db.add(evidence_rec)
            evidence_schemas.append(
                EvidenceItemSchema(
                    id=item.rule_code,
                    rule_name=item.rule_code,
                    layer=item.layer_name,
                    score_impact=item.score_contribution,
                    description=item.description,
                    confidence=item.confidence,
                    metadata=item.details,
                )
            )

        await self.db.commit()

        return ScanResponse(
            scan_id=str(scan.id),
            url=parsed.raw_url,
            normalized_url=parsed.normalized_url,
            domain=parsed.host,
            verdict=risk_report.verdict.value,
            risk_score=risk_report.risk_score,
            confidence=risk_report.confidence,
            evidence=evidence_schemas,
            threat_sources=confirmed_sources,
            scan_duration_ms=elapsed_ms,
            scanned_at=datetime.now(timezone.utc).isoformat(),
            engine_version=risk_report.engine_version,
        )

    async def get_scan_by_id(self, scan_id: uuid.UUID) -> Optional[ScanResponse]:
        """Lookup a past scan with itemized evidence by ID."""
        query = (
            select(Scan)
            .where(Scan.id == scan_id)
            .options(selectinload(Scan.evidence))
        )
        result = await self.db.execute(query)
        scan = result.scalars().first()
        if not scan:
            return None

        evidence_schemas = [
            EvidenceItemSchema(
                id=str(e.id),
                rule_name=e.rule_code,
                layer=e.layer_name,
                score_impact=e.score_contribution,
                description=e.evidence_data.get("description", ""),
                confidence=e.confidence,
                metadata=e.evidence_data,
            )
            for e in scan.evidence
        ]

        return ScanResponse(
            scan_id=str(scan.id),
            url=scan.url,
            normalized_url=scan.normalized_url,
            domain=scan.domain,
            verdict=scan.verdict.value,
            risk_score=scan.risk_score,
            confidence=scan.confidence,
            evidence=evidence_schemas,
            threat_sources=[],
            scan_duration_ms=scan.scan_duration_ms,
            scanned_at=scan.created_at.isoformat(),
            engine_version=scan.engine_version,
        )

    async def get_history(
        self,
        user_id: Optional[uuid.UUID] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> ScanHistoryResponse:
        """Query recent scan history."""
        query = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
        if user_id:
            query = query.where(Scan.user_id == user_id)

        result = await self.db.execute(query)
        scans = result.scalars().all()

        scan_responses = [
            ScanResponse(
                scan_id=str(s.id),
                url=s.url,
                normalized_url=s.normalized_url,
                domain=s.domain,
                verdict=s.verdict.value,
                risk_score=s.risk_score,
                confidence=s.confidence,
                evidence=[],
                threat_sources=[],
                scan_duration_ms=s.scan_duration_ms,
                scanned_at=s.created_at.isoformat(),
                engine_version=s.engine_version,
            )
            for s in scans
        ]

        return ScanHistoryResponse(total=len(scan_responses), scans=scan_responses)
