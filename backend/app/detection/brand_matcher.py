"""
Layer 2: Brand Impersonation, Homoglyph Detection, and Lookalike Domain Matcher.
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from app.detection.url_parser import ParsedURL


@dataclass(frozen=True)
class BrandMatchResult:
    """Result of brand impersonation evaluation."""
    is_impersonating: bool
    brand_name: Optional[str] = None
    match_type: Optional[str] = None
    similarity_score: float = 0.0
    confidence: float = 0.0
    score_contribution: float = 0.0
    evidence_message: str = ""


class BrandMatcher:
    """Engine detecting deceptive brand impersonation, typosquatting, and homoglyphs."""

    # Cyrillic and visual lookalikes to Latin characters
    HOMOGLYPH_MAP: Dict[str, str] = {
        # Cyrillic
        "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s",
        "х": "x", "у": "y", "і": "i", "ј": "j", "ԁ": "d", "ԛ": "q",
        "ӏ": "l", "ԍ": "g", "в": "b", "п": "n", "т": "t",
        # Greek
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "κ": "k",
        # Common Leetspeak / Typosquatting digit lookalikes
        "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "8": "b",
    }

    # Reference Brand Catalog: Brand Name -> Set of authorized registrable domains
    BRAND_CATALOG: Dict[str, Set[str]] = {
        "paypal": {"paypal.com", "paypal-communication.com", "paypalobjects.com"},
        "google": {"google.com", "youtube.com", "gmail.com", "googleusercontent.com", "google.co.uk", "google.co.in"},
        "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "azure.com"},
        "apple": {"apple.com", "icloud.com"},
        "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"},
        "netflix": {"netflix.com"},
        "chase": {"chase.com"},
        "bankofamerica": {"bankofamerica.com", "bofa.com"},
        "facebook": {"facebook.com", "fb.com", "instagram.com", "whatsapp.com", "meta.com"},
        "wellsfargo": {"wellsfargo.com"},
        "coinbase": {"coinbase.com"},
        "binance": {"binance.com"},
        "dropbox": {"dropbox.com"},
        "adobe": {"adobe.com"},
        "linkedin": {"linkedin.com"},
        "twitter": {"twitter.com", "x.com"},
    }

    @classmethod
    def normalize_homoglyphs(cls, text: str) -> str:
        """Replace visual homoglyphs and lookalike characters with canonical Latin."""
        return "".join(cls.HOMOGLYPH_MAP.get(char, char) for char in text.lower())

    @classmethod
    def levenshtein_distance(cls, s1: str, s2: str) -> int:
        """Compute minimum edit distance between two strings using dynamic programming."""
        if len(s1) < len(s2):
            return cls.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    @classmethod
    def evaluate(cls, parsed: ParsedURL) -> BrandMatchResult:
        """Evaluate a URL for brand impersonation, typosquatting, or homoglyphs."""
        reg_domain = parsed.registered_domain.lower()
        subdomain = parsed.subdomain.lower()
        decoded_host = parsed.decoded_host.lower()
        path = parsed.path.lower()

        # Step 1: Check if the domain is legitimately owned by the brand
        for brand, legit_domains in cls.BRAND_CATALOG.items():
            for legit in legit_domains:
                if reg_domain == legit or reg_domain.endswith("." + legit):
                    return BrandMatchResult(
                        is_impersonating=False,
                        brand_name=brand,
                        evidence_message=f"Verified legitimate domain for {brand.title()}",
                    )

        # Extract domain name without TLD (e.g. 'paypal' from 'paypal.com' or 'paypa1' from 'paypa1.xyz')
        domain_label = reg_domain.split(".")[0] if "." in reg_domain else reg_domain
        normalized_label = cls.normalize_homoglyphs(domain_label)

        # Step 2: Lookalike domain matching (Levenshtein distance <= 2 or homoglyph match)
        # Check both full domain label and hyphen-separated tokens (e.g. 'paypa1-verify')
        label_tokens = [domain_label] + [t for t in domain_label.split("-") if t]

        for token in label_tokens:
            token_normalized = cls.normalize_homoglyphs(token)
            for brand, legit_domains in cls.BRAND_CATALOG.items():
                brand_len = len(brand)

                # Check homoglyph equivalence (e.g. paypаl or paypa1 -> paypal)
                if token_normalized == brand and token != brand:
                    return BrandMatchResult(
                        is_impersonating=True,
                        brand_name=brand,
                        match_type="HOMOGLYPH_MATCH",
                        similarity_score=1.0,
                        confidence=0.98,
                        score_contribution=45.0,
                        evidence_message=f"Host uses deceptive character substitutions mimicking {brand.title()} in '{domain_label}'",
                    )

                # If token matches brand exactly but is embedded in a compound domain (e.g. paypal-security.xyz)
                if token == brand and domain_label != brand:
                    return BrandMatchResult(
                        is_impersonating=True,
                        brand_name=brand,
                        match_type="COMPOUND_DOMAIN_BRAND_DECEPTION",
                        similarity_score=0.95,
                        confidence=0.92,
                        score_contribution=40.0,
                        evidence_message=f"Brand '{brand.title()}' appears in compound domain '{reg_domain}'",
                    )

                # Check edit-distance typosquatting (for brand names >= 4 characters)
                if brand_len >= 4:
                    dist = cls.levenshtein_distance(token, brand)
                    norm_dist = cls.levenshtein_distance(token_normalized, brand)
                    min_dist = min(dist, norm_dist)

                    max_allowed_dist = 1 if brand_len <= 6 else 2
                    if 1 <= min_dist <= max_allowed_dist and abs(len(token) - brand_len) <= 2:
                        sim = 1.0 - (min_dist / max(len(token), brand_len))
                        return BrandMatchResult(
                            is_impersonating=True,
                            brand_name=brand,
                            match_type="TYPOSQUAT_LOOKALIKE",
                            similarity_score=round(sim, 2),
                            confidence=0.92,
                            score_contribution=40.0,
                            evidence_message=f"Domain token '{token}' in '{reg_domain}' is a visual lookalike of {brand.title()} (edit distance: {min_dist})",
                        )

        # Step 3: Subdomain Hijacking (brand name placed in subdomain of an unrelated domain)
        # e.g., paypal.com.verify-account.top or accounts.google.com.phishing.xyz
        for brand in cls.BRAND_CATALOG.keys():
            if brand in subdomain:
                # Confirm it's not a legitimate brand sub-brand
                return BrandMatchResult(
                    is_impersonating=True,
                    brand_name=brand,
                    match_type="SUBDOMAIN_BRAND_DECEPTION",
                    similarity_score=0.9,
                    confidence=0.90,
                    score_contribution=35.0,
                    evidence_message=f"Brand '{brand.title()}' appears in subdomain on third-party domain '{reg_domain}'",
                )

        # Step 4: Brand keyword in path on an IP address host or high-risk TLD
        if parsed.is_ip or parsed.tld in {"xyz", "top", "work", "tk", "click"}:
            for brand in cls.BRAND_CATALOG.keys():
                if f"/{brand}" in path or f"={brand}" in parsed.query:
                    return BrandMatchResult(
                        is_impersonating=True,
                        brand_name=brand,
                        match_type="PATH_BRAND_DECEPTION",
                        similarity_score=0.8,
                        confidence=0.85,
                        score_contribution=30.0,
                        evidence_message=f"Brand '{brand.title()}' referenced on untrusted host '{parsed.host}'",
                    )

        return BrandMatchResult(is_impersonating=False)
