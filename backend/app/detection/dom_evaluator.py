"""
Layer 4: DOM and Credential-Form Structural Signal Evaluator.
"""
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.detection.url_parser import ParsedURL, URLNormalizer


class DOMSignals(BaseModel):
    """Client-submitted structural DOM indicators (strictly zero user secrets)."""
    page_url: str
    has_password_field: bool = False
    has_login_form: bool = False
    form_action_hosts: List[str] = Field(default_factory=list)
    has_ip_form_action: bool = False
    has_cross_origin_form: bool = False
    hidden_iframe_count: int = 0
    external_script_count: int = 0


@dataclass
class DOMEvaluationResult:
    """Evaluation result for DOM structural indicators."""
    score_contribution: float = 0.0
    confidence: float = 0.0
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)


class DOMSignalEvaluator:
    """Evaluates client-extracted DOM signals for credential harvesting patterns."""

    @classmethod
    def evaluate(cls, signals: DOMSignals, page_parsed: Optional[ParsedURL] = None) -> DOMEvaluationResult:
        """Evaluate DOM signals against credential-harvesting heuristics."""
        if not page_parsed:
            page_parsed = URLNormalizer.parse(signals.page_url)

        total_score = 0.0
        evidence_list: List[Dict[str, Any]] = []
        confidences: List[float] = []

        page_host = page_parsed.host.lower()

        # Check 1: Password field submitting to an IP address
        if signals.has_password_field and signals.has_ip_form_action:
            score = 45.0
            total_score += score
            confidences.append(0.98)
            evidence_list.append({
                "rule_code": "DOM_PASSWORD_IP_DESTINATION",
                "layer_name": "dom_indicators",
                "score_contribution": score,
                "confidence": 0.98,
                "description": "Password input submits credentials directly to an IP address destination",
                "details": {"action_hosts": signals.form_action_hosts},
            })

        # Check 2: Password field submitting to cross-origin destination
        elif signals.has_password_field and signals.has_cross_origin_form:
            # Verify if action hosts differ from page host and registered domain
            external_hosts = [
                h for h in signals.form_action_hosts
                if h and not (h == page_host or h.endswith("." + page_parsed.registered_domain))
            ]
            if external_hosts:
                score = 35.0
                total_score += score
                confidences.append(0.92)
                evidence_list.append({
                    "rule_code": "DOM_PASSWORD_CROSS_ORIGIN",
                    "layer_name": "dom_indicators",
                    "score_contribution": score,
                    "confidence": 0.92,
                    "description": f"Login form submits credentials across origins to external host(s): {', '.join(external_hosts)}",
                    "details": {"external_hosts": external_hosts},
                })

        # Check 3: Password form hosted on insecure HTTP
        if signals.has_password_field and page_parsed.scheme == "http":
            score = 20.0
            total_score += score
            confidences.append(0.88)
            evidence_list.append({
                "rule_code": "DOM_PASSWORD_OVER_HTTP",
                "layer_name": "dom_indicators",
                "score_contribution": score,
                "confidence": 0.88,
                "description": "Password input detected on insecure unencrypted HTTP protocol",
                "details": {"scheme": "http"},
            })

        # Check 4: Anomalous hidden iframes (> 2)
        if signals.hidden_iframe_count > 2:
            score = 15.0
            total_score += score
            confidences.append(0.80)
            evidence_list.append({
                "rule_code": "DOM_EXCESSIVE_HIDDEN_IFRAMES",
                "layer_name": "dom_indicators",
                "score_contribution": score,
                "confidence": 0.80,
                "description": f"Page contains {signals.hidden_iframe_count} hidden iframes (potential clickjacking or cloaking)",
                "details": {"hidden_iframe_count": signals.hidden_iframe_count},
            })

        avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.5
        return DOMEvaluationResult(
            score_contribution=min(50.0, total_score),
            confidence=avg_confidence,
            evidence_items=evidence_list,
        )

