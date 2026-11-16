"""
Automated Pytest suite testing Brand Impersonation, DOM Indicators,
High-Priority Overrides, and Layer 7 Explainable Risk Scoring.
"""
import pytest
from app.detection.brand_matcher import BrandMatcher
from app.detection.dom_evaluator import DOMSignalEvaluator, DOMSignals
from app.detection.scoring import RiskEngine, RiskReport
from app.detection.url_parser import URLNormalizer
from app.models.scan import ScanVerdict


def test_brand_matcher_homoglyph_detection():
    """Verify detection of Cyrillic/homoglyph character substitution."""
    # "pаypal" where 'а' is Cyrillic \u0430
    homoglyph_url = "http://p\u0430ypal.com/login"
    parsed = URLNormalizer.parse(homoglyph_url)
    result = BrandMatcher.evaluate(parsed)

    assert result.is_impersonating is True
    assert result.brand_name == "paypal"
    assert result.match_type == "HOMOGLYPH_MATCH"
    assert result.score_contribution >= 40.0


def test_brand_matcher_typosquatting_lookalike():
    """Verify Levenshtein edit-distance detection of lookalike domains."""
    typo_url = "http://paypaal.com/update"
    parsed = URLNormalizer.parse(typo_url)
    result = BrandMatcher.evaluate(parsed)

    assert result.is_impersonating is True
    assert result.brand_name == "paypal"
    assert result.match_type == "TYPOSQUAT_LOOKALIKE"


def test_brand_matcher_subdomain_hijacking():
    """Verify detection of brand names embedded in subdomains on third-party domains."""
    subdomain_phish = "https://paypal.com.account-update.xyz/login"
    parsed = URLNormalizer.parse(subdomain_phish)
    result = BrandMatcher.evaluate(parsed)

    assert result.is_impersonating is True
    assert result.brand_name == "paypal"
    assert result.match_type == "SUBDOMAIN_BRAND_DECEPTION"


def test_brand_matcher_legitimate_exemptions():
    """Ensure legitimate brand domains are never flagged as impersonating themselves."""
    legit_cases = [
        "https://www.paypal.com/signin",
        "https://accounts.google.com/ServiceLogin",
        "https://login.microsoftonline.com/common/oauth2",
        "https://appleid.apple.com/account",
        "https://www.amazon.com/ap/signin",
    ]
    for url in legit_cases:
        parsed = URLNormalizer.parse(url)
        result = BrandMatcher.evaluate(parsed)
        assert result.is_impersonating is False, f"False positive on legitimate domain: {url}"


def test_dom_evaluator_password_to_ip_destination():
    """Verify DOM evaluator flags password forms submitting to IP addresses."""
    signals = DOMSignals(
        page_url="http://banking-portal.net/login",
        has_password_field=True,
        has_ip_form_action=True,
        form_action_hosts=["192.168.1.50"],
    )
    result = DOMSignalEvaluator.evaluate(signals)

    assert result.score_contribution >= 40.0
    assert result.confidence >= 0.90
    assert any(e["rule_code"] == "DOM_PASSWORD_IP_DESTINATION" for e in result.evidence_items)


def test_dom_evaluator_password_cross_origin():
    """Verify DOM evaluator flags password forms submitting to external origins."""
    signals = DOMSignals(
        page_url="https://secure-login.corporate.com/login",
        has_password_field=True,
        has_cross_origin_form=True,
        form_action_hosts=["attacker-harvest-server.xyz"],
    )
    result = DOMSignalEvaluator.evaluate(signals)

    assert result.score_contribution >= 30.0
    assert any(e["rule_code"] == "DOM_PASSWORD_CROSS_ORIGIN" for e in result.evidence_items)


def test_risk_engine_policy_allowlist_override():
    """Verify explicit allowlist match triggers immediate SAFE verdict (Score 0)."""
    # Suspicious-looking URL that is explicitly allowlisted
    url = "http://192.168.1.1:8080/internal/admin?user=admin@company"
    report = RiskEngine.evaluate(
        url=url,
        is_allowlisted=True,
        allowlist_reason="Enterprise internal intranet portal",
    )

    assert report.verdict == ScanVerdict.SAFE
    assert report.risk_score == 0.0
    assert report.is_override is True
    assert report.override_reason == "ALLOWLIST"
    assert report.evidence[0].rule_code == "POLICY_ALLOWLIST_OVERRIDE"


def test_risk_engine_threat_feed_override():
    """Verify confirmed threat feed match triggers immediate PHISHING verdict (Score 100)."""
    url = "http://fresh-phish-kit-active.xyz/login.html"
    report = RiskEngine.evaluate(
        url=url,
        is_threat_feed_match=True,
        threat_feed_source="URLhaus Active Malicious Database",
    )

    assert report.verdict == ScanVerdict.PHISHING
    assert report.risk_score == 100.0
    assert report.is_override is True
    assert report.override_reason == "THREAT_FEED_MATCH"
    assert report.evidence[0].rule_code == "THREAT_FEED_CONFIRMED_MATCH"


def test_risk_engine_composite_phishing_scoring():
    """Verify composite scoring on a multi-layer deceptive phishing URL."""
    # Deceptive URL: brand homoglyph + high-risk TLD + credential keyword + cross-origin password DOM
    url = "http://paypa1-account-verify.xyz/login.php"
    dom = DOMSignals(
        page_url=url,
        has_password_field=True,
        has_cross_origin_form=True,
        form_action_hosts=["drop-harvest.top"],
    )
    report = RiskEngine.evaluate(url=url, dom_signals=dom)

    assert report.verdict == ScanVerdict.PHISHING
    assert report.risk_score >= 70.0
    assert report.confidence >= 0.85
    assert len(report.evidence) >= 3

    # Ensure evidence codes match expected layers
    rule_codes = [e.rule_code for e in report.evidence]
    assert any(c.startswith("BRAND_") for c in rule_codes)
    assert any(c.startswith("URL_") for c in rule_codes)
    assert any(c.startswith("DOM_") for c in rule_codes)


def test_risk_engine_safe_verdict():
    """Verify clean legitimate site produces SAFE verdict with low score."""
    url = "https://www.google.com/search?q=cybersecurity"
    report = RiskEngine.evaluate(url=url)

    assert report.verdict == ScanVerdict.SAFE
    assert report.risk_score < 30.0
    assert report.is_override is False
