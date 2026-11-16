"""
30+ Lexical, structural, statistical, and Shannon entropy URL feature extraction engine.
"""
import math
import re
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Set

from app.detection.url_parser import ParsedURL, URLNormalizer


@dataclass(frozen=True)
class URLFeatures:
    """Structured representation of extracted URL features."""
    # Structural lengths
    url_length: int
    hostname_length: int
    path_length: int
    query_length: int

    # Delimiter counts
    num_dots: int
    num_hyphens: int
    num_underscores: int
    num_slashes: int
    num_question_marks: int
    num_equal_signs: int
    num_at_symbols: int
    num_ampersands: int
    num_exclamations: int
    num_tildes: int
    num_percent_signs: int

    # Subdomain analysis
    subdomain_count: int
    subdomain_depth: int

    # Host & Protocol properties
    is_ip_host: bool
    ip_version: int
    has_port: bool
    is_standard_port: bool
    has_https: bool
    has_punycode: bool

    # Shannon Entropies
    entropy_url: float
    entropy_host: float
    entropy_path: float

    # Character distributions & ratios
    digits_ratio_host: float
    digits_ratio_url: float
    vowel_ratio_host: float
    consonant_ratio_host: float
    max_consecutive_consonants: int

    # Content & Reputation indicators
    num_suspicious_keywords: int
    suspicious_keywords_detected: List[str]
    high_risk_tld: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert features dataclass to dictionary."""
        return asdict(self)


class FeatureExtractor:
    """Engine extracting 30+ explainable security features from URLs."""

    SUSPICIOUS_KEYWORDS: Set[str] = {
        "login", "signin", "sign-in", "log-in", "verify", "verification",
        "account", "banking", "secure", "security", "update", "wallet",
        "confirm", "confirmation", "password", "credential", "authenticate",
        "support", "billing", "service", "portal", "oauth", "recover",
        "validation", "authorize", "free-gift", "claim-reward",
    }

    HIGH_RISK_TLDS: Set[str] = {
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
        "buzz", "fit", "loan", "stream", "gdn", "racing", "vip", "party",
        "men", "country", "review",
    }

    VOWELS: Set[str] = set("aeiou")

    @classmethod
    def calculate_shannon_entropy(cls, text: str) -> float:
        """Calculate Shannon information entropy (in bits) of a given string."""
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        entropy = -sum((count / length) * math.log2(count / length) for count in counts.values())
        return round(entropy, 4)

    @classmethod
    def extract_from_parsed(cls, parsed: ParsedURL) -> URLFeatures:
        """Extract all 30+ features from an already parsed and normalized URL."""
        url = parsed.normalized_url
        raw_url = parsed.raw_url
        host = parsed.host
        path = parsed.path
        query = parsed.query

        # Structural lengths
        url_len = len(url)
        host_len = len(host)
        path_len = len(path)
        query_len = len(query)

        # Delimiter counts (measured on original raw input to catch obfuscation & userinfo abuse)
        num_dots = raw_url.count(".")
        num_hyphens = raw_url.count("-")
        num_underscores = raw_url.count("_")
        num_slashes = raw_url.count("/")
        num_question_marks = raw_url.count("?")
        num_equal_signs = raw_url.count("=")
        num_at_symbols = raw_url.count("@")
        num_ampersands = raw_url.count("&")
        num_exclamations = raw_url.count("!")
        num_tildes = raw_url.count("~")
        num_percent_signs = raw_url.count("%")

        # Subdomain analysis
        subdomain_parts = [p for p in parsed.subdomain.split(".") if p]
        subdomain_count = len(subdomain_parts)
        subdomain_depth = len(parsed.subdomain) if parsed.subdomain else 0

        # Protocol & Port
        has_port = parsed.port is not None
        is_standard_port = (parsed.port is None) or (
            parsed.scheme == "http" and parsed.port == 80
        ) or (
            parsed.scheme == "https" and parsed.port == 443
        )

        # Entropies
        entropy_url = cls.calculate_shannon_entropy(url)
        entropy_host = cls.calculate_shannon_entropy(host)
        entropy_path = cls.calculate_shannon_entropy(path)

        # Character ratios on host
        host_alpha_num = re.sub(r"[^a-zA-Z0-9]", "", host)
        host_digits = sum(1 for c in host if c.isdigit())
        digits_ratio_host = round(host_digits / max(1, len(host)), 4)

        url_digits = sum(1 for c in url if c.isdigit())
        digits_ratio_url = round(url_digits / max(1, len(url)), 4)

        alpha_host = [c.lower() for c in host if c.isalpha()]
        alpha_count = len(alpha_host)
        if alpha_count > 0:
            vowels = sum(1 for c in alpha_host if c in cls.VOWELS)
            consonants = alpha_count - vowels
            vowel_ratio_host = round(vowels / alpha_count, 4)
            consonant_ratio_host = round(consonants / alpha_count, 4)
        else:
            vowel_ratio_host = 0.0
            consonant_ratio_host = 0.0

        # Max consecutive consonants (DGA / randomness indicator)
        consecutive_consonants = 0
        max_consecutive_consonants = 0
        for c in host.lower():
            if c.isalpha() and c not in cls.VOWELS:
                consecutive_consonants += 1
                if consecutive_consonants > max_consecutive_consonants:
                    max_consecutive_consonants = consecutive_consonants
            else:
                consecutive_consonants = 0

        # Keywords detection
        lower_url = url.lower()
        matched_keywords = [kw for kw in cls.SUSPICIOUS_KEYWORDS if kw in lower_url]

        # TLD check
        high_risk_tld = parsed.tld.lower() in cls.HIGH_RISK_TLDS

        return URLFeatures(
            url_length=url_len,
            hostname_length=host_len,
            path_length=path_len,
            query_length=query_len,
            num_dots=num_dots,
            num_hyphens=num_hyphens,
            num_underscores=num_underscores,
            num_slashes=num_slashes,
            num_question_marks=num_question_marks,
            num_equal_signs=num_equal_signs,
            num_at_symbols=num_at_symbols,
            num_ampersands=num_ampersands,
            num_exclamations=num_exclamations,
            num_tildes=num_tildes,
            num_percent_signs=num_percent_signs,
            subdomain_count=subdomain_count,
            subdomain_depth=subdomain_depth,
            is_ip_host=parsed.is_ip,
            ip_version=parsed.ip_version or 0,
            has_port=has_port,
            is_standard_port=is_standard_port,
            has_https=parsed.scheme == "https",
            has_punycode=parsed.has_punycode,
            entropy_url=entropy_url,
            entropy_host=entropy_host,
            entropy_path=entropy_path,
            digits_ratio_host=digits_ratio_host,
            digits_ratio_url=digits_ratio_url,
            vowel_ratio_host=vowel_ratio_host,
            consonant_ratio_host=consonant_ratio_host,
            max_consecutive_consonants=max_consecutive_consonants,
            num_suspicious_keywords=len(matched_keywords),
            suspicious_keywords_detected=matched_keywords,
            high_risk_tld=high_risk_tld,
        )

    @classmethod
    def extract(cls, raw_url: str) -> URLFeatures:
        """Convenience method parsing URL and extracting features directly."""
        parsed = URLNormalizer.parse(raw_url)
        return cls.extract_from_parsed(parsed)
