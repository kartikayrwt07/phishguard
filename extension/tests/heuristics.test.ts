import { describe, it, expect } from 'vitest';
import { URLNormalizer } from '../src/detection/url_parser';
import {
  calculateShannonEntropy,
  HeuristicEngine,
  levenshteinDistance,
  normalizeHomoglyphs,
} from '../src/detection/heuristics';

describe('Client-Side URL Normalizer', () => {
  it('normalizes standard schemes, ports, and query parameters', () => {
    const parsed = URLNormalizer.parse('HTTPS://EXAMPLE.COM:443/login//path?b=2&a=1#section');
    expect(parsed.scheme).toBe('https');
    expect(parsed.host).toBe('example.com');
    expect(parsed.port).toBeUndefined(); // 443 stripped for https
    expect(parsed.path).toBe('/login/path');
    expect(parsed.query).toBe('a=1&b=2'); // sorted
    expect(parsed.normalized_url).toBe('https://example.com/login/path?a=1&b=2');
  });

  it('correctly separates multi-part public suffixes', () => {
    const ukParsed = URLNormalizer.parse('https://service.gov.uk/portal');
    expect(ukParsed.tld).toBe('gov.uk');
    expect(ukParsed.root_domain).toBe('service.gov.uk');

    const auParsed = URLNormalizer.parse('http://sub.banking.com.au/login');
    expect(auParsed.tld).toBe('com.au');
    expect(auParsed.root_domain).toBe('banking.com.au');
    expect(auParsed.subdomains).toBe('sub');
  });

  it('detects raw IPv4 and IPv6 literal hostnames', () => {
    const ipv4 = URLNormalizer.parse('http://192.168.1.1:8080/admin');
    expect(ipv4.is_ip).toBe(true);
    expect(ipv4.ip_version).toBe(4);
    expect(ipv4.host).toBe('192.168.1.1');

    const ipv6 = URLNormalizer.parse('http://[2001:db8::1]/index');
    expect(ipv6.is_ip).toBe(true);
    expect(ipv6.ip_version).toBe(6);
    expect(ipv6.host).toBe('2001:db8::1');
  });
});

describe('Heuristic Signal Evaluators', () => {
  it('computes Shannon entropy with expected characteristics', () => {
    const lowEntropy = calculateShannonEntropy('aaaaaa');
    expect(lowEntropy).toBe(0);

    const moderateEntropy = calculateShannonEntropy('example.com');
    expect(moderateEntropy).toBeGreaterThan(2.5);

    const highEntropy = calculateShannonEntropy('x7k9q2m4z1p8w3v5');
    expect(highEntropy).toBeGreaterThan(3.5);
  });

  it('normalizes homoglyph substitutions to canonical ASCII', () => {
    expect(normalizeHomoglyphs('pаypаl')).toBe('paypal'); // Cyrillic а
    expect(normalizeHomoglyphs('micros0ft')).toBe('microsoft'); // 0 -> o
    expect(normalizeHomoglyphs('paypa1')).toBe('paypal'); // 1 -> l
    expect(normalizeHomoglyphs('twiiter')).toBe('twiiter');
  });

  it('calculates Levenshtein distance accurately', () => {
    expect(levenshteinDistance('paypal', 'paypal')).toBe(0);
    expect(levenshteinDistance('paypal', 'paypaal')).toBe(1);
    expect(levenshteinDistance('google', 'g00gle')).toBe(2);
  });
});

describe('HeuristicEngine Brand Impersonation & Scoring', () => {
  it('detects brand homoglyphs and visual lookalikes', () => {
    // Cyrillic homoglyph
    const resHomoglyph = HeuristicEngine.analyze('http://pаypal.com/verify');
    expect(resHomoglyph.score).toBeGreaterThanOrEqual(50);
    expect(resHomoglyph.evidence.some((e) => e.rule_name === 'HOMOGLYPH_MATCH')).toBe(true);

    // Typosquat lookalike
    const resTyposquat = HeuristicEngine.analyze('http://paypaal.com/signin');
    expect(resTyposquat.score).toBeGreaterThanOrEqual(45);
    expect(resTyposquat.evidence.some((e) => e.rule_name === 'TYPOSQUAT_LOOKALIKE')).toBe(true);

    // Compound domain lookalike
    const resCompound = HeuristicEngine.analyze('http://paypa1-account-security.xyz/update');
    expect(resCompound.score).toBeGreaterThanOrEqual(70);
    expect(resCompound.verdict).toBe('PHISHING');
  });

  it('guarantees legitimate brand domains never flag false positives', () => {
    const legitPayPal = HeuristicEngine.analyze('https://www.paypal.com/signin');
    expect(legitPayPal.verdict).toBe('SAFE');
    expect(legitPayPal.score).toBe(0);
    expect(legitPayPal.evidence.length).toBe(0);

    const legitGoogle = HeuristicEngine.analyze('https://accounts.google.com/ServiceLogin');
    expect(legitGoogle.verdict).toBe('SAFE');
    expect(legitGoogle.score).toBe(0);

    const legitAmazon = HeuristicEngine.analyze('https://aws.amazon.com/console');
    expect(legitAmazon.verdict).toBe('SAFE');
    expect(legitAmazon.score).toBe(0);
  });

  it('flags combination of raw IP, suspicious keywords, and excessive hyphens', () => {
    const phishingUrl = 'http://192.168.1.100/login/verify-account-security';
    const result = HeuristicEngine.analyze(phishingUrl);

    expect(result.score).toBeGreaterThanOrEqual(50);
    expect(result.evidence.some((e) => e.rule_name === 'RAW_IP_HOST')).toBe(true);
    expect(result.evidence.some((e) => e.rule_name === 'SUSPICIOUS_KEYWORD_DENSITY')).toBe(true);
  });

  it('strictly satisfies the sub-15ms performance SLA across 100 evaluations', () => {
    const testUrls = [
      'https://www.google.com/search?q=cybersecurity',
      'http://paypa1-security-verification.xyz/login.php?user=test',
      'http://192.168.1.50/admin/credentials',
      'https://accounts.google.com/signin/v2/identifier',
      'http://bankofamerica-login-update.cam/confirm',
      'https://github.com/microsoft/vscode',
      'http://netflix-billing-renew.xyz/account',
      'https://en.wikipedia.org/wiki/Phishing',
    ];

    const iterations = 100;
    const start = performance.now();

    for (let i = 0; i < iterations; i++) {
      const url = testUrls[i % testUrls.length];
      const res = HeuristicEngine.analyze(url);
      expect(res.verdict).toBeDefined();
    }

    const totalDurationMs = performance.now() - start;
    const avgDurationMs = totalDurationMs / iterations;

    // SLA: sub-15ms per evaluation
    expect(avgDurationMs).toBeLessThan(15);
  });
});
