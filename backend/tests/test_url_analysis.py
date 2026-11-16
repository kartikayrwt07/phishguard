"""
Comprehensive automated Pytest suite for URL Normalizer and Feature Extractor.
"""
import pytest
from app.detection.url_parser import URLNormalizer, ParsedURL
from app.detection.features import FeatureExtractor, URLFeatures


def test_url_normalizer_standard_cleanup():
    """Verify standard normalization of casing, default ports, and paths."""
    raw = "HTTPS://WWW.Google.COM:443/search/../search/?q=security&hl=en#section"
    parsed = URLNormalizer.parse(raw)

    assert parsed.scheme == "https"
    assert parsed.host == "www.google.com"
    assert parsed.port is None  # 443 stripped for https
    assert parsed.path == "/search/"
    assert parsed.query == "hl=en&q=security"  # sorted query params
    assert parsed.subdomain == "www"
    assert parsed.registered_domain == "google.com"
    assert parsed.tld == "com"
    assert parsed.is_ip is False
    assert parsed.has_punycode is False
    assert parsed.normalized_url == "https://www.google.com/search/?hl=en&q=security"


def test_url_normalizer_multipart_tlds():
    """Verify correct domain separation for multi-part TLDs (e.g. .co.uk, .com.au)."""
    parsed = URLNormalizer.parse("https://online.banking.hsbc.co.uk/portal/login")

    assert parsed.tld == "co.uk"
    assert parsed.registered_domain == "hsbc.co.uk"
    assert parsed.subdomain == "online.banking"


def test_url_normalizer_raw_ip_hosts():
    """Verify parsing of raw IPv4, IPv6, and non-standard ports."""
    # IPv4 with custom port
    ipv4_url = "http://192.168.1.100:8080/config.php"
    p_ipv4 = URLNormalizer.parse(ipv4_url)
    assert p_ipv4.is_ip is True
    assert p_ipv4.ip_version == 4
    assert p_ipv4.port == 8080
    assert p_ipv4.host == "192.168.1.100"

    # IPv6
    ipv6_url = "http://[2001:db8::1]/index.html"
    p_ipv6 = URLNormalizer.parse(ipv6_url)
    assert p_ipv6.is_ip is True
    assert p_ipv6.ip_version == 6
    assert p_ipv6.host == "2001:db8::1"


def test_url_normalizer_encoded_ip_formats():
    """Verify detection of hex and decimal encoded IPv4 addresses."""
    # Hex encoded 127.0.0.1
    hex_url = "http://0x7f000001/admin"
    p_hex = URLNormalizer.parse(hex_url)
    assert p_hex.is_ip is True
    assert p_hex.ip_version == 4
    assert p_hex.host == "127.0.0.1"

    # Decimal encoded 127.0.0.1 (2130706433)
    dec_url = "http://2130706433/login"
    p_dec = URLNormalizer.parse(dec_url)
    assert p_dec.is_ip is True
    assert p_dec.ip_version == 4
    assert p_dec.host == "127.0.0.1"


def test_url_normalizer_punycode():
    """Verify decoding of Punycode IDNA domains."""
    # xn--apple-43a.com is "apple" with cyrillic 'а'
    puny_url = "https://xn--pple-43d.com/login"
    p_puny = URLNormalizer.parse(puny_url)
    assert p_puny.has_punycode is True
    assert p_puny.host == "xn--pple-43d.com"
    assert p_puny.decoded_host != p_puny.host


def test_shannon_entropy_calculation():
    """Verify Shannon entropy mathematical properties."""
    # Monotonous string should have zero entropy
    assert FeatureExtractor.calculate_shannon_entropy("aaaaaaa") == 0.0

    # Binary string with equal distribution has entropy 1.0
    assert FeatureExtractor.calculate_shannon_entropy("abababab") == 1.0

    # Complex random string has high entropy
    high_entropy = FeatureExtractor.calculate_shannon_entropy("x7k9!q2#L0$z1&mP")
    assert high_entropy > 3.5


def test_feature_extraction_phishing_indicators():
    """Verify extraction of 30+ features on a representative phishing URL."""
    phish_url = "http://paypal.account.verification.secure-portal.xyz:8080/login.php?user=test@victim.com&action=confirm"
    features = FeatureExtractor.extract(phish_url)

    assert features.url_length > 50
    assert features.hostname_length > 20
    assert features.subdomain_count >= 3
    assert features.is_ip_host is False
    assert features.has_port is True
    assert features.is_standard_port is False
    assert features.has_https is False
    assert features.num_at_symbols >= 1
    assert features.high_risk_tld is True  # .xyz is high risk
    assert features.num_suspicious_keywords >= 4
    assert "login" in features.suspicious_keywords_detected
    assert "account" in features.suspicious_keywords_detected
    assert "secure" in features.suspicious_keywords_detected
    assert "verification" in features.suspicious_keywords_detected

    # Ensure to_dict converts all fields
    d = features.to_dict()
    assert len(d) >= 30
    assert isinstance(d["entropy_url"], float)
    assert isinstance(d["digits_ratio_host"], float)


def test_feature_extraction_legitimate_indicators():
    """Verify extraction on a clean, legitimate URL."""
    clean_url = "https://github.com/google/antigravity"
    features = FeatureExtractor.extract(clean_url)

    assert features.has_https is True
    assert features.is_ip_host is False
    assert features.has_port is False
    assert features.is_standard_port is True
    assert features.high_risk_tld is False
    assert features.num_suspicious_keywords == 0
    assert features.num_at_symbols == 0
    assert features.subdomain_count == 0


def test_malformed_url_resilience():
    """Verify normalizer and feature extractor handle empty or malformed inputs without crashing."""
    for malformed in ["", "   ", "not_a_url", "http://", "https:///"]:
        parsed = URLNormalizer.parse(malformed)
        features = FeatureExtractor.extract_from_parsed(parsed)
        assert isinstance(features, URLFeatures)
        assert features.url_length >= 0
