"""
SSRF-Safe HTTP Client with DNS Pre-Resolution, IP Validation, and Socket Pinning.
Defends against Server-Side Request Forgery (SSRF) and DNS Rebinding (TOCTOU) attacks.
"""
import ipaddress
import socket
from typing import Any, Dict, List, Optional
import urllib.parse
import httpx


class SSRFProtectionError(Exception):
    """Raised when an outbound request targets a forbidden, internal, or private network."""
    pass


# Prohibited CIDR blocks for outbound requests
PROHIBITED_NETWORKS = [
    # IPv4 loopback
    ipaddress.ip_network("127.0.0.0/8"),
    # IPv4 RFC 1918 private
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    # IPv4 RFC 3927 link-local (includes AWS/GCP/Azure metadata 169.254.169.254)
    ipaddress.ip_network("169.254.0.0/16"),
    # Carrier-grade NAT RFC 6598
    ipaddress.ip_network("100.64.0.0/10"),
    # Test networks RFC 5737
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    # Benchmark RFC 2544
    ipaddress.ip_network("198.18.0.0/15"),
    # Multicast & Reserved
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    # Broadcast / current network
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.255/32"),
    # IPv6 loopback
    ipaddress.ip_network("::1/128"),
    # IPv6 unspecified
    ipaddress.ip_network("::/128"),
    # IPv6 unique local (RFC 4193)
    ipaddress.ip_network("fc00::/7"),
    # IPv6 link-local (RFC 4291)
    ipaddress.ip_network("fe80::/10"),
    # IPv6 documentation (RFC 3849)
    ipaddress.ip_network("2001:db8::/32"),
    # IPv6 multicast
    ipaddress.ip_network("ff00::/8"),
]


def is_ip_prohibited(ip_str: str) -> bool:
    """
    Check if an IPv4 or IPv6 address belongs to any prohibited/private/reserved network.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True

    # Standard python attributes
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True

    # Check explicit network definitions (e.g. carrier-grade NAT, benchmark networks)
    for network in PROHIBITED_NETWORKS:
        if ip in network:
            return True

    return False


def resolve_and_validate_host(host: str) -> List[str]:
    """
    Pre-resolves host via socket.getaddrinfo and validates that ALL resolved IP addresses
    belong to permissible public internet space.

    Raises:
        SSRFProtectionError: If any resolved address is prohibited or host cannot be resolved.
    """
    clean_host = host.strip("[]")
    
    # Check if host is already a raw IP literal
    try:
        ip = ipaddress.ip_address(clean_host)
        if is_ip_prohibited(str(ip)):
            raise SSRFProtectionError(f"Target IP '{clean_host}' is in a prohibited or private network range.")
        return [str(ip)]
    except ValueError:
        pass  # Host is a DNS domain name

    # Resolve via DNS
    try:
        addrinfo = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise SSRFProtectionError(f"DNS resolution failed for host '{clean_host}': {e}") from e

    if not addrinfo:
        raise SSRFProtectionError(f"Host '{clean_host}' resolved to no IP addresses.")

    resolved_ips: List[str] = []
    for entry in addrinfo:
        sockaddr = entry[4]
        ip_addr = sockaddr[0]
        if ip_addr not in resolved_ips:
            resolved_ips.append(ip_addr)

    # Validate EVERY resolved IP address to prevent dual-homed / split-DNS evasion
    for ip_addr in resolved_ips:
        if is_ip_prohibited(ip_addr):
            raise SSRFProtectionError(
                f"Host '{clean_host}' resolved to prohibited IP '{ip_addr}'. Request aborted for SSRF protection."
            )

    return resolved_ips


class SSRFSafeClient:
    """
    Async HTTP client designed to safely fetch external resources without exposing
    internal services, cloud metadata, or falling victim to DNS rebinding (TOCTOU).
    """

    def __init__(
        self,
        timeout_seconds: float = 5.0,
        max_redirects: int = 3,
        verify_ssl: bool = True,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_redirects = max_redirects
        self.verify_ssl = verify_ssl

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """
        Execute an outbound HTTP request with pre-DNS resolution, IP validation, socket pinning,
        and step-by-step redirect inspection.
        """
        current_url = url
        redirects_remaining = self.max_redirects
        req_headers = dict(headers) if headers else {}

        while True:
            parsed = urllib.parse.urlsplit(current_url)

            # Scheme validation: strictly http or https
            if parsed.scheme.lower() not in ("http", "https"):
                raise SSRFProtectionError(
                    f"Unsupported or dangerous URI scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."
                )

            # Reject userinfo in URL to avoid URL parsing discrepancies
            if parsed.username or parsed.password:
                raise SSRFProtectionError("URLs containing userinfo (username/password) are prohibited.")

            if not parsed.hostname:
                raise SSRFProtectionError(f"Invalid URL without hostname: '{current_url}'")

            hostname = parsed.hostname
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)

            # 1. Pre-resolve and validate all IP addresses
            resolved_ips = resolve_and_validate_host(hostname)
            pinned_ip = resolved_ips[0]

            # 2. Construct pinned URL: connect directly to pinned IP to defeat DNS rebinding (TOCTOU)
            is_ipv6 = ":" in pinned_ip
            ip_host_repr = f"[{pinned_ip}]" if is_ipv6 else pinned_ip

            # Path with query
            path_query = parsed.path or "/"
            if parsed.query:
                path_query = f"{path_query}?{parsed.query}"

            pinned_url = f"{parsed.scheme}://{ip_host_repr}:{port}{path_query}"

            # 3. Configure headers: set Host header to preserve original virtual host
            step_headers = dict(req_headers)
            if (parsed.scheme == "http" and port == 80) or (parsed.scheme == "https" and port == 443):
                step_headers["Host"] = hostname
            else:
                step_headers["Host"] = f"{hostname}:{port}"

            # 4. Configure extensions for SNI hostname verification in TLS
            extensions: Dict[str, Any] = {}
            if parsed.scheme.lower() == "https":
                extensions["sni_hostname"] = hostname

            # 5. Make the request with follow_redirects=False to control every redirect hop
            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=self.timeout_seconds,
                follow_redirects=False,
            ) as client:
                response = await client.request(
                    method=method,
                    url=pinned_url,
                    headers=step_headers,
                    json=json,
                    data=data,
                    params=params,
                    extensions=extensions,
                )

            # 6. Step-by-step redirect validation
            if response.is_redirect and "location" in response.headers:
                if redirects_remaining <= 0:
                    raise SSRFProtectionError("Too many redirects: exceeded maximum redirect budget.")

                redirects_remaining -= 1
                location = response.headers["location"]
                current_url = urllib.parse.urljoin(current_url, location)
                # Next loop iteration will validate the new target URL from scratch
                continue

            return response

    async def get(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        return await self.request("GET", url, headers=headers, params=params)

    async def post(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> httpx.Response:
        return await self.request("POST", url, headers=headers, json=json, data=data)

