/**
 * Client-Side Heuristic Scoring Engine and Brand Impersonation Matcher.
 * Executes offline in the Service Worker in under 15ms.
 */

import { ScanEvidenceItem, ScanResult, ScanVerdict } from '../shared/types';
import { ParsedURL, URLNormalizer } from './url_parser';

export interface BrandReference {
  name: string;
  primary_domains: string[];
}

export const BRAND_CATALOG: BrandReference[] = [
  { name: 'google', primary_domains: ['google.com', 'google.co.uk', 'google.co.in', 'gstatic.com', 'youtube.com'] },
  { name: 'microsoft', primary_domains: ['microsoft.com', 'live.com', 'office.com', 'azure.com', 'windows.com', 'sharepoint.com'] },
  { name: 'apple', primary_domains: ['apple.com', 'icloud.com'] },
  { name: 'paypal', primary_domains: ['paypal.com', 'paypal.me'] },
  { name: 'amazon', primary_domains: ['amazon.com', 'amazon.co.uk', 'aws.amazon.com'] },
  { name: 'netflix', primary_domains: ['netflix.com'] },
  { name: 'chase', primary_domains: ['chase.com'] },
  { name: 'facebook', primary_domains: ['facebook.com', 'fb.com', 'meta.com'] },
  { name: 'instagram', primary_domains: ['instagram.com'] },
  { name: 'twitter', primary_domains: ['twitter.com', 'x.com'] },
  { name: 'linkedin', primary_domains: ['linkedin.com'] },
  { name: 'dropbox', primary_domains: ['dropbox.com'] },
  { name: 'adobe', primary_domains: ['adobe.com'] },
  { name: 'wellsfargo', primary_domains: ['wellsfargo.com'] },
  { name: 'bankofamerica', primary_domains: ['bankofamerica.com'] },
  { name: 'binance', primary_domains: ['binance.com'] },
];

const HOMOGLYPHS: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b',
};

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'security', 'account',
  'update', 'banking', 'secure', 'confirm', 'credential', 'wallet',
  'authenticate', 'support', 'recover', 'billing', 'password',
];

const HIGH_RISK_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'work', 'icu', 'cam', 'monster',
]);

/**
 * Compute Shannon Entropy of a string.
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;
  const len = str.length;
  const freqs: Record<string, number> = {};

  for (let i = 0; i < len; i++) {
    const ch = str[i];
    freqs[ch] = (freqs[ch] || 0) + 1;
  }

  let entropy = 0;
  for (const ch in freqs) {
    const p = freqs[ch] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Fast Levenshtein distance calculation.
 */
export function levenshteinDistance(s1: string, s2: string): number {
  const m = s1.length;
  const n = s2.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (s1[i - 1] === s2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }

  return dp[m][n];
}

/**
 * Normalize homoglyphs and numbers into canonical ASCII.
 */
export function normalizeHomoglyphs(str: string): string {
  let normalized = str.toLowerCase().replace(/vv/g, 'w');
  let result = '';
  for (let i = 0; i < normalized.length; i++) {
    const ch = normalized[i];
    result += HOMOGLYPHS[ch] || ch;
  }
  return result;
}

export interface BrandMatchResult {
  matchedBrand: string;
  matchedRule: 'HOMOGLYPH_MATCH' | 'TYPOSQUAT_LOOKALIKE' | 'SUBDOMAIN_HIJACK' | 'KEYWORD_PLACEMENT';
  evidence: string;
  scoreImpact: number;
}

export class HeuristicEngine {
  /**
   * Check if a host belongs legitimately to a brand.
   */
  static isLegitimateBrandDomain(host: string, brand: BrandReference): boolean {
    const cleanHost = host.toLowerCase();
    for (const legit of brand.primary_domains) {
      if (cleanHost === legit || cleanHost.endsWith(`.${legit}`)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Evaluate brand lookalikes, homoglyphs, and tokenized hijacking.
   */
  static checkBrandImpersonation(parsed: ParsedURL): BrandMatchResult | null {
    if (parsed.is_ip || !parsed.host) {
      return null;
    }

    // Inspect both Unicode host (before IDNA/Punycode) and ASCII host
    const candidates = [parsed.unicode_host || parsed.host];
    if (parsed.unicode_host !== parsed.host) {
      candidates.push(parsed.host);
    }

    for (const candidate of candidates) {
      const hostParts = candidate.split('.');
      const sld = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : candidate;
      const sldTokens = sld.split('-');

      for (const brand of BRAND_CATALOG) {
        // 1. If legitimate domain, never flag
        if (this.isLegitimateBrandDomain(parsed.host, brand)) {
          continue;
        }

        const brandName = brand.name;
        const normalizedSld = normalizeHomoglyphs(sld);

        // 2. Homoglyph direct match
        if (normalizedSld === brandName && sld !== brandName) {
          return {
            matchedBrand: brandName,
            matchedRule: 'HOMOGLYPH_MATCH',
            evidence: `Domain '${parsed.host}' uses homoglyphs mimicking protected brand '${brandName}'.`,
            scoreImpact: 55,
          };
        }

        // 3. Typo-squatting / Levenshtein distance on SLD
        const distance = levenshteinDistance(sld, brandName);
        const maxAllowedDist = brandName.length >= 7 ? 2 : 1;
        if (distance > 0 && distance <= maxAllowedDist) {
          return {
            matchedBrand: brandName,
            matchedRule: 'TYPOSQUAT_LOOKALIKE',
            evidence: `Domain '${parsed.host}' is a visual lookalike (edit distance ${distance}) of brand '${brandName}'.`,
            scoreImpact: 45,
          };
        }

        // 4. Tokenized lookalike on hyphen-separated domain labels (e.g. paypa1-account-verify)
        for (const token of sldTokens) {
          const normToken = normalizeHomoglyphs(token);
          if (normToken === brandName && token !== brandName) {
            return {
              matchedBrand: brandName,
              matchedRule: 'HOMOGLYPH_MATCH',
              evidence: `Domain component '${token}' uses homoglyphs impersonating brand '${brandName}'.`,
              scoreImpact: 55,
            };
          }
          const tokenDist = levenshteinDistance(token, brandName);
          if (tokenDist > 0 && tokenDist <= maxAllowedDist) {
            return {
              matchedBrand: brandName,
              matchedRule: 'TYPOSQUAT_LOOKALIKE',
              evidence: `Domain component '${token}' mimics protected brand '${brandName}'.`,
              scoreImpact: 45,
            };
          }
        }

        // 5. Subdomain hijacking (e.g. paypal.com.evil.xyz)
        if (parsed.subdomains) {
          const subParts = parsed.subdomains.split('.');
          if (subParts.includes(brandName) || subParts.some((p) => normalizeHomoglyphs(p) === brandName)) {
            return {
              matchedBrand: brandName,
              matchedRule: 'SUBDOMAIN_HIJACK',
              evidence: `Subdomain explicitly impersonates brand '${brandName}' on an unrelated root domain.`,
              scoreImpact: 50,
            };
          }
        }
      }
    }

    return null;
  }

  /**
   * Fast offline heuristic analysis executing in <15ms.
   */
  static analyze(url: string, sensitivityThreshold: number = 50): ScanResult {
    const startTime = performance.now();
    const parsed = URLNormalizer.parse(url);

    // If host is a recognized legitimate brand domain, return SAFE immediately
    const isLegitBrand = BRAND_CATALOG.some((b) => this.isLegitimateBrandDomain(parsed.host, b));
    if (isLegitBrand) {
      const elapsedMs = performance.now() - startTime;
      return {
        url: parsed.normalized_url || url,
        domain: parsed.host,
        verdict: 'SAFE',
        score: 0,
        confidence: 0.99,
        evidence: [],
        source: 'local',
        scanned_at: new Date().toISOString(),
        engine_version: `heuristics-1.0.0 (${elapsedMs.toFixed(2)}ms)`,
      };
    }

    const evidence: ScanEvidenceItem[] = [];
    let score = 0;

    // 1. Raw IP address hostname
    if (parsed.is_ip) {
      score += 35;
      evidence.push({
        id: 'ip_hostname',
        rule_name: 'RAW_IP_HOST',
        layer: 'url_lexical',
        score_impact: 35,
        description: `URL uses raw IP address '${parsed.host}' as hostname instead of a domain name.`,
        confidence: 0.9,
      });
    }

    // 2. High-Risk TLD
    if (parsed.tld && HIGH_RISK_TLDS.has(parsed.tld.toLowerCase())) {
      score += 15;
      evidence.push({
        id: 'high_risk_tld',
        rule_name: 'HIGH_RISK_TLD',
        layer: 'url_lexical',
        score_impact: 15,
        description: `Domain uses top-level domain '.${parsed.tld}', frequently leveraged for disposable phishing campaigns.`,
        confidence: 0.7,
      });
    }

    // 3. Userinfo / @ symbol in raw URL
    if (parsed.raw_url.includes('@')) {
      score += 30;
      evidence.push({
        id: 'userinfo_delimiter',
        rule_name: 'USERINFO_DELIMITER_AT',
        layer: 'url_lexical',
        score_impact: 30,
        description: "URL contains '@' delimiter, commonly used to disguise destination credentials.",
        confidence: 0.85,
      });
    }

    // 4. Excessive Subdomain Depth
    if (parsed.subdomains) {
      const subCount = parsed.subdomains.split('.').length;
      if (subCount >= 3) {
        score += 15;
        evidence.push({
          id: 'excessive_subdomains',
          rule_name: 'EXCESSIVE_SUBDOMAINS',
          layer: 'url_lexical',
          score_impact: 15,
          description: `Hostname contains ${subCount} subdomain levels, indicating potential routing obfuscation.`,
          confidence: 0.75,
        });
      }
    }

    // 5. Suspicious Keywords in Host or Path
    const targetText = `${parsed.host}/${parsed.path}`.toLowerCase();
    const matchedKeywords = SUSPICIOUS_KEYWORDS.filter((kw) => targetText.includes(kw));
    if (matchedKeywords.length >= 2) {
      score += 20;
      evidence.push({
        id: 'suspicious_keywords',
        rule_name: 'SUSPICIOUS_KEYWORD_DENSITY',
        layer: 'url_lexical',
        score_impact: 20,
        description: `URL contains multiple high-risk credential keywords: ${matchedKeywords.slice(0, 4).join(', ')}.`,
        confidence: 0.8,
      });
    } else if (matchedKeywords.length === 1 && (parsed.is_ip || parsed.subdomains)) {
      score += 10;
      evidence.push({
        id: 'suspicious_keyword_single',
        rule_name: 'SUSPICIOUS_KEYWORD_PATH',
        layer: 'url_lexical',
        score_impact: 10,
        description: `URL path contains credential keyword '${matchedKeywords[0]}' on non-standard host.`,
        confidence: 0.65,
      });
    }

    // 6. Shannon Entropy
    const hostEntropy = calculateShannonEntropy(parsed.host);
    const pathEntropy = calculateShannonEntropy(parsed.path);
    if (hostEntropy > 3.8 && !parsed.is_ip) {
      score += 15;
      evidence.push({
        id: 'high_host_entropy',
        rule_name: 'HIGH_HOST_ENTROPY',
        layer: 'statistical',
        score_impact: 15,
        description: `Hostname exhibits unusually high Shannon entropy (${hostEntropy.toFixed(2)} bits), suggesting algorithmic generation (DGA).`,
        confidence: 0.75,
      });
    } else if (pathEntropy > 4.5 && parsed.path.length > 20) {
      score += 10;
      evidence.push({
        id: 'high_path_entropy',
        rule_name: 'HIGH_PATH_ENTROPY',
        layer: 'statistical',
        score_impact: 10,
        description: `URL path contains high-entropy randomized tokens (${pathEntropy.toFixed(2)} bits).`,
        confidence: 0.6,
      });
    }

    // 7. Brand Impersonation & Homoglyphs
    const brandMatch = this.checkBrandImpersonation(parsed);
    if (brandMatch) {
      score += brandMatch.scoreImpact;
      evidence.push({
        id: `brand_${brandMatch.matchedBrand}`,
        rule_name: brandMatch.matchedRule,
        layer: 'brand_impersonation',
        score_impact: brandMatch.scoreImpact,
        description: brandMatch.evidence,
        confidence: 0.95,
      });
    }

    // Clamp score to [0, 100]
    const finalScore = Math.min(100, Math.max(0, score));

    // Determine verdict based on user sensitivity threshold
    let verdict: ScanVerdict = 'SAFE';
    if (finalScore >= 70) {
      verdict = 'PHISHING';
    } else if (finalScore >= Math.min(sensitivityThreshold, 69)) {
      verdict = 'SUSPICIOUS';
    }

    // Derived confidence
    let confidence = 0.5;
    if (evidence.length >= 3 || brandMatch) {
      confidence = 0.95;
    } else if (evidence.length === 2) {
      confidence = 0.8;
    } else if (evidence.length === 1) {
      confidence = 0.65;
    } else {
      confidence = 0.9; // Clean URLs have high confidence SAFE
    }

    const elapsedMs = performance.now() - startTime;

    return {
      url: parsed.normalized_url || url,
      domain: parsed.host,
      verdict,
      score: finalScore,
      confidence,
      evidence,
      source: 'local',
      scanned_at: new Date().toISOString(),
      engine_version: `heuristics-1.0.0 (${elapsedMs.toFixed(2)}ms)`,
    };
  }
}
