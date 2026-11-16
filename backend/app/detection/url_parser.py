"""
Safe, RFC 3986-compliant URL normalization, canonicalization, and parsing module.
"""
import ipaddress
import posixpath
import re
from dataclasses import dataclass
from typing import Optional, Tuple
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class ParsedURL:
    """Immutable representation of a normalized and parsed URL."""
    raw_url: str
    normalized_url: str
    scheme: str
    host: str
    decoded_host: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    is_ip: bool
    ip_version: Optional[int]
    has_punycode: bool
    subdomain: str
    registered_domain: str
    tld: str


class URLNormalizer:
    """Production-grade URL parser and canonicalizer designed for phishing detection."""

    # Common two-part TLDs (e.g., .co.uk, .com.au)
    MULTI_PART_TLDS = {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
        "co.nz", "net.nz", "co.jp", "ne.jp", "com.br", "com.mx", "co.in",
        "net.in", "org.in", "gov.in", "co.za", "com.sg", "com.hk",
    }

    @classmethod
    def parse(cls, url: str) -> ParsedURL:
        """Parse, validate, and canonicalize a URL string."""
        if not url or not isinstance(url, str):
            url = ""

        raw_url = url.strip()

        # 1. Normalize scheme (default to http if missing scheme)
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
            url_with_scheme = "http://" + raw_url
        else:
            url_with_scheme = raw_url

        try:
            parts = urlsplit(url_with_scheme)
        except ValueError:
            # Fallback for malformed URLs
            parts = urlsplit("http://malformed.invalid")

        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            scheme = "http"

        # 2. Extract and normalize hostname and port
        netloc = parts.netloc
        # Strip userinfo if present
        if "@" in netloc:
            netloc = netloc.split("@", 1)[1]

        host = ""
        port: Optional[int] = None

        if ":" in netloc and not netloc.endswith("]"):  # Guard against IPv6 [::1]:port
            host_part, port_part = netloc.rsplit(":", 1)
            try:
                port = int(port_part)
                # Strip default ports
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    port = None
            except ValueError:
                port = None
            host = host_part.lower()
        else:
            host = netloc.lower()

        # Clean host bracket notation for IPv6
        clean_host = host.strip("[]")
        host = clean_host

        # 3. Detect IP address (IPv4 or IPv6)
        is_ip = False
        ip_version: Optional[int] = None
        try:
            ip_obj = ipaddress.ip_address(clean_host)
            is_ip = True
            ip_version = ip_obj.version
        except ValueError:
            # Check integer or hex encoded IPs (e.g. 0x7f000001 or 2130706433)
            if re.match(r"^(0x[0-9a-fA-F]+|[0-9]{8,10})$", clean_host):
                try:
                    int_val = int(clean_host, 16 if clean_host.startswith("0x") else 10)
                    ip_obj = ipaddress.IPv4Address(int_val)
                    is_ip = True
                    ip_version = 4
                    clean_host = str(ip_obj)
                    host = clean_host
                except (ValueError, OverflowError):
                    pass

        # 4. Punycode (IDNA) processing
        has_punycode = "xn--" in host
        decoded_host = host
        if has_punycode:
            try:
                decoded_host = host.encode("utf-8").decode("idna")
            except Exception:
                decoded_host = host

        # 5. Extract subdomain, registered domain, and TLD
        subdomain, registered_domain, tld = cls._extract_domain_parts(decoded_host, is_ip)

        # 6. Normalize path
        raw_path = parts.path or "/"
        # Resolve /./ and /../ safely
        normalized_path = posixpath.normpath(unquote(raw_path))
        if raw_path.endswith("/") and not normalized_path.endswith("/"):
            normalized_path += "/"
        if not normalized_path.startswith("/"):
            normalized_path = "/" + normalized_path

        # 7. Normalize query string
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_pairs))

        # 8. Reconstruct normalized URL
        formatted_host = f"[{host}]" if ip_version == 6 else host
        normalized_netloc = formatted_host
        if port is not None:
            normalized_netloc = f"{formatted_host}:{port}"

        normalized_url = urlunsplit((scheme, normalized_netloc, normalized_path, sorted_query, ""))

        return ParsedURL(
            raw_url=raw_url,
            normalized_url=normalized_url,
            scheme=scheme,
            host=host,
            decoded_host=decoded_host,
            port=port,
            path=normalized_path,
            query=sorted_query,
            fragment=parts.fragment,
            is_ip=is_ip,
            ip_version=ip_version,
            has_punycode=has_punycode,
            subdomain=subdomain,
            registered_domain=registered_domain,
            tld=tld,
        )

    @classmethod
    def _extract_domain_parts(cls, host: str, is_ip: bool) -> Tuple[str, str, str]:
        """Split a host into (subdomain, registered_domain, tld)."""
        if is_ip or not host or "." not in host:
            return "", host, ""

        labels = host.split(".")
        if len(labels) < 2:
            return "", host, ""

        # Check multi-part TLD (e.g. .co.uk)
        last_two = ".".join(labels[-2:])
        if last_two in cls.MULTI_PART_TLDS and len(labels) >= 3:
            tld = last_two
            registered_domain = f"{labels[-3]}.{last_two}"
            subdomain = ".".join(labels[:-3])
            return subdomain, registered_domain, tld

        tld = labels[-1]
        registered_domain = f"{labels[-2]}.{labels[-1]}"
        subdomain = ".".join(labels[:-2])
        return subdomain, registered_domain, tld
