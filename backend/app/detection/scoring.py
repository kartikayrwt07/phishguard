"""
Layer 7: Explainable Risk Scoring Engine and High-Priority Policy Overrides.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.core.config import settings
from app.detection.brand_matcher import BrandMatchResult, BrandMatcher
from app.detection.dom_evaluator import DOMEvaluationResult, DOMSignalEvaluator, DOMSignals
from app.detection.features import FeatureExtractor, URLFeatures
from app.detection.url_parser import ParsedURL, URLNormalizer
from app.models.scan import ScanVerdict


@dataclass(frozen=True)
class EvidenceItem:
    """An individual piece of explainable detection evidence."""
    rule_code: str
    layer_name: str
    score_contribution: float
    confidence: float
    description: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RiskReport:
    """Consolidated explainable detection report."""
    url: str
    normalized_url: str
    domain: str
    verdict: ScanVerdict
    risk_score: float
    confidence: float
    engine_version: str
    evidence: List[EvidenceItem]
    is_override: bool = False
    override_reason: Optional[str] = None
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "verdict": self.verdict.value,
            "risk_score": round(self.risk_score, 1),
            "confidence": round(self.confidence, 2),
            "engine_version": self.engine_version,
            "is_override": self.is_override,
            "override_reason": self.override_reason,
            "evaluated_at": self.evaluated_at,
            "evidence": [e.to_dict() for e in self.evidence],
        }


class RiskEngine:
    """Orchestrates multi-layer detection and outputs explainable risk scores."""

    ENGINE_VERSION = "1.0.0"

    @classmethod
    def evaluate(
        cls,
        url: str,
        dom_signals: Optional[DOMSignals] = None,
        is_threat_feed_match: bool = False,
        threat_feed_source: Optional[str] = None,
        is_allowlisted: bool = False,
        allowlist_reason: Optional[str] = None,
    ) -> RiskReport:
        """Run all detection layers and compute composite risk score and verdict."""
        parsed = URLNormalizer.parse(url)
        evidence_list: List[EvidenceItem] = []

        # Policy Override 1: Explicit Allowlist Match (Score 0, SAFE)
        if is_allowlisted:
            reason = allowlist_reason or "Domain is present on enterprise or user allowlist"
            evidence_list.append(EvidenceItem(
                rule_code="POLICY_ALLOWLIST_OVERRIDE",
                layer_name="policy",
                score_contribution=0.0,
                confidence=1.0,
                description=reason,
                details={"domain": parsed.registered_domain},
            ))
            return RiskReport(
                url=parsed.raw_url,
                normalized_url=parsed.normalized_url,
                domain=parsed.registered_domain,
                verdict=ScanVerdict.SAFE,
                risk_score=0.0,
                confidence=1.0,
                engine_version=cls.ENGINE_VERSION,
                evidence=evidence_list,
                is_override=True,
                override_reason="ALLOWLIST",
            )

        # Policy Override 2: Confirmed Threat Intelligence Match (Score 100, PHISHING)
        if is_threat_feed_match:
            source = threat_feed_source or "Threat Intelligence Feed"
            evidence_list.append(EvidenceItem(
                rule_code="THREAT_FEED_CONFIRMED_MATCH",
                layer_name="threat_intelligence",
                score_contribution=100.0,
                confidence=1.0,
                description=f"Destination matches known confirmed threat indicator in {source}",
                details={"source": source, "indicator": parsed.normalized_url},
            ))
            return RiskReport(
                url=parsed.raw_url,
                normalized_url=parsed.normalized_url,
                domain=parsed.registered_domain,
                verdict=ScanVerdict.PHISHING,
                risk_score=100.0,
                confidence=1.0,
                engine_version=cls.ENGINE_VERSION,
                evidence=evidence_list,
                is_override=True,
                override_reason="THREAT_FEED_MATCH",
            )

        total_score = 0.0
        confidences: List[float] = []

        # Layer 1: URL Feature Analysis
        features = FeatureExtractor.extract_from_parsed(parsed)

        # Rule: IP address used as hostname
        if features.is_ip_host:
            score = 30.0
            total_score += score
            confidences.append(0.95)
            evidence_list.append(EvidenceItem(
                rule_code="URL_RAW_IP_HOSTNAME",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.95,
                description=f"Hostname is a direct IP address ({parsed.host}) rather than a registered domain",
                details={"host": parsed.host, "ip_version": features.ip_version},
            ))

        # Rule: At-symbol in URL (credential obfuscation)
        if features.num_at_symbols > 0:
            score = 25.0
            total_score += score
            confidences.append(0.92)
            evidence_list.append(EvidenceItem(
                rule_code="URL_AT_SYMBOL_OBFUSCATION",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.92,
                description="URL contains '@' delimiter, commonly used to disguise destination hosts",
                details={"count": features.num_at_symbols},
            ))

        # Rule: Punycode character encoding
        if features.has_punycode:
            score = 25.0
            total_score += score
            confidences.append(0.90)
            evidence_list.append(EvidenceItem(
                rule_code="URL_PUNYCODE_IDN",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.90,
                description=f"Domain uses Punycode/IDN encoding: '{parsed.host}' decodes to '{parsed.decoded_host}'",
                details={"raw_host": parsed.host, "decoded_host": parsed.decoded_host},
            ))

        # Rule: High-risk TLD
        if features.high_risk_tld:
            score = 15.0
            total_score += score
            confidences.append(0.80)
            evidence_list.append(EvidenceItem(
                rule_code="URL_HIGH_RISK_TLD",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.80,
                description=f"Top-level domain '.{parsed.tld}' has elevated association with phishing campaigns",
                details={"tld": parsed.tld},
            ))

        # Rule: High hostname Shannon entropy (> 3.8)
        if features.entropy_host > 3.8 and not features.is_ip_host:
            score = 15.0
            total_score += score
            confidences.append(0.85)
            evidence_list.append(EvidenceItem(
                rule_code="URL_HIGH_HOSTNAME_ENTROPY",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.85,
                description=f"Hostname demonstrates elevated Shannon entropy ({features.entropy_host} bits), suggesting algorithmic generation (DGA)",
                details={"entropy": features.entropy_host},
            ))

        # Rule: Non-standard port
        if not features.is_standard_port and features.has_port:
            score = 15.0
            total_score += score
            confidences.append(0.85)
            evidence_list.append(EvidenceItem(
                rule_code="URL_NON_STANDARD_PORT",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.85,
                description=f"Web service operates on non-standard port {parsed.port}",
                details={"port": parsed.port},
            ))

        # Rule: Excessive subdomains (> 2)
        if features.subdomain_count > 2:
            score = 15.0
            total_score += score
            confidences.append(0.80)
            evidence_list.append(EvidenceItem(
                rule_code="URL_EXCESSIVE_SUBDOMAINS",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.80,
                description=f"URL contains {features.subdomain_count} subdomain levels, indicating deceptive nesting",
                details={"subdomain": parsed.subdomain, "count": features.subdomain_count},
            ))

        # Rule: Suspicious credential keywords
        if features.num_suspicious_keywords > 0:
            score = min(25.0, features.num_suspicious_keywords * 10.0)
            total_score += score
            confidences.append(0.85)
            evidence_list.append(EvidenceItem(
                rule_code="URL_SUSPICIOUS_KEYWORDS",
                layer_name="url_analysis",
                score_contribution=score,
                confidence=0.85,
                description=f"URL includes high-risk security keywords: {', '.join(features.suspicious_keywords_detected)}",
                details={"keywords": features.suspicious_keywords_detected},
            ))

        # Layer 2: Brand Impersonation Matching
        brand_result: BrandMatchResult = BrandMatcher.evaluate(parsed)
        if brand_result.is_impersonating:
            total_score += brand_result.score_contribution
            confidences.append(brand_result.confidence)
            evidence_list.append(EvidenceItem(
                rule_code=f"BRAND_{brand_result.match_type}",
                layer_name="brand_impersonation",
                score_contribution=brand_result.score_contribution,
                confidence=brand_result.confidence,
                description=brand_result.evidence_message,
                details={
                    "brand": brand_result.brand_name,
                    "match_type": brand_result.match_type,
                    "similarity": brand_result.similarity_score,
                },
            ))

        # Layer 4: DOM Indicator Evaluation (if client provided DOM signals)
        if dom_signals:
            dom_result: DOMEvaluationResult = DOMSignalEvaluator.evaluate(dom_signals, parsed)
            total_score += dom_result.score_contribution
            if dom_result.evidence_items:
                confidences.append(dom_result.confidence)
                for item in dom_result.evidence_items:
                    evidence_list.append(EvidenceItem(
                        rule_code=item["rule_code"],
                        layer_name=item["layer_name"],
                        score_contribution=item["score_contribution"],
                        confidence=item["confidence"],
                        description=item["description"],
                        details=item.get("details", {}),
                    ))

        # Aggregate and bound score
        final_score = min(100.0, max(0.0, total_score))
        avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.70

        # Determine Verdict
        if final_score >= settings.MIN_PHISHING_THRESHOLD:
            verdict = ScanVerdict.PHISHING
        elif final_score >= settings.MIN_SUSPICIOUS_THRESHOLD:
            verdict = ScanVerdict.SUSPICIOUS
        else:
            verdict = ScanVerdict.SAFE

        return RiskReport(
            url=parsed.raw_url,
            normalized_url=parsed.normalized_url,
            domain=parsed.registered_domain or parsed.host,
            verdict=verdict,
            risk_score=final_score,
            confidence=avg_confidence,
            engine_version=cls.ENGINE_VERSION,
            evidence=evidence_list,
        )

