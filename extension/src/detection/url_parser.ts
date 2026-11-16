/**
 * Safe, Standards-Compliant Client-Side URL Normalizer and Canonicalizer.
 * Optimized for lightweight execution inside the Chrome Extension Service Worker.
 */

export interface ParsedURL {
  raw_url: string;
  normalized_url: string;
  scheme: string;
  host: string;
  unicode_host: string;
  port?: number;
  path: string;
  query: string;
  fragment: string;
  root_domain: string;
  subdomains: string;
  tld: string;
  is_ip: boolean;
  ip_version?: 4 | 6;
}

// Common multi-part public suffixes
const MULTIPART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp',
  'co.in', 'net.in', 'org.in', 'gov.in',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.sg', 'edu.sg', 'gov.sg',
  'co.za', 'org.za', 'gov.za',
]);

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;
const IPV6_REGEX = /^\[?[0-9a-fA-F:]+\]?$/;

export class URLNormalizer {
  /**
   * Normalize and parse a raw URL string safely.
   */
  static parse(rawUrl: string): ParsedURL {
    const trimmed = (rawUrl || '').trim();
    if (!trimmed) {
      return this.emptyParsedURL(rawUrl);
    }

    // Default to http scheme if missing
    let target = trimmed;
    if (!target.includes('://')) {
      target = `http://${target}`;
    }

    try {
      const parsed = new URL(target);
      const scheme = parsed.protocol.replace(':', '').toLowerCase();
      let host = parsed.hostname.toLowerCase();
      if (host.startsWith('[') && host.endsWith(']')) {
        host = host.slice(1, -1);
      }

      // Extract unicode host from target before punycode conversion
      let unicodeHost = host;
      const protoIndex = target.indexOf('://');
      if (protoIndex !== -1) {
        const withoutProto = target.slice(protoIndex + 3);
        const slashIndex = withoutProto.search(/[\/\?#]/);
        const hostPort = slashIndex !== -1 ? withoutProto.slice(0, slashIndex) : withoutProto;
        const rawHost = hostPort.split(':')[0].toLowerCase();
        if (rawHost) {
          unicodeHost = rawHost;
        }
      }

      // Check for IP literal
      const isIpv4 = IPV4_REGEX.test(host);
      const isIpv6 = !isIpv4 && host.includes(':') && IPV6_REGEX.test(host);
      const isIp = isIpv4 || isIpv6;

      // Extract port
      let port: number | undefined = parsed.port ? parseInt(parsed.port, 10) : undefined;
      if ((scheme === 'http' && port === 80) || (scheme === 'https' && port === 443)) {
        port = undefined;
      }

      // Decompose domain components
      const { rootDomain, subdomains, tld } = this.extractDomainParts(host, isIp);

      // Path and query normalization
      let path = parsed.pathname || '/';
      // Normalize double slashes
      path = path.replace(/\/+/g, '/');

      // Sort query parameters for deterministic matching
      let query = '';
      if (parsed.searchParams) {
        const params: [string, string][] = [];
        parsed.searchParams.forEach((val, key) => params.push([key, val]));
        params.sort((a, b) => a[0].localeCompare(b[0]));
        if (params.length > 0) {
          query = params
            .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
            .join('&');
        }
      }

      // Construct normalized URL
      const hostPart = isIpv6 ? `[${host}]` : host;
      const portPart = port ? `:${port}` : '';
      const queryPart = query ? `?${query}` : '';
      const normalizedUrl = `${scheme}://${hostPart}${portPart}${path}${queryPart}`;

      return {
        raw_url: rawUrl,
        normalized_url: normalizedUrl,
        scheme,
        host,
        unicode_host: unicodeHost,
        port,
        path,
        query,
        fragment: parsed.hash.replace(/^#/, ''),
        root_domain: rootDomain,
        subdomains,
        tld,
        is_ip: isIp,
        ip_version: isIpv4 ? 4 : isIpv6 ? 6 : undefined,
      };
    } catch {
      return this.emptyParsedURL(rawUrl);
    }
  }

  private static extractDomainParts(
    host: string,
    isIp: boolean
  ): { rootDomain: string; subdomains: string; tld: string } {
    if (isIp || !host.includes('.')) {
      return { rootDomain: host, subdomains: '', tld: '' };
    }

    const parts = host.split('.');
    if (parts.length <= 1) {
      return { rootDomain: host, subdomains: '', tld: '' };
    }

    // Check for 2-part TLD (e.g. co.uk)
    if (parts.length >= 3) {
      const twoPartTld = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`.toLowerCase();
      if (MULTIPART_TLDS.has(twoPartTld)) {
        const rootDomain = `${parts[parts.length - 3]}.${twoPartTld}`;
        const subdomains = parts.slice(0, parts.length - 3).join('.');
        return { rootDomain, subdomains, tld: twoPartTld };
      }
    }

    // Standard single-part TLD
    const tld = parts[parts.length - 1];
    const rootDomain = `${parts[parts.length - 2]}.${tld}`;
    const subdomains = parts.slice(0, parts.length - 2).join('.');
    return { rootDomain, subdomains, tld };
  }

  private static emptyParsedURL(raw: string): ParsedURL {
    return {
      raw_url: raw,
      normalized_url: raw,
      scheme: 'http',
      host: '',
      unicode_host: '',
      path: '/',
      query: '',
      fragment: '',
      root_domain: '',
      subdomains: '',
      tld: '',
      is_ip: false,
    };
  }
}
