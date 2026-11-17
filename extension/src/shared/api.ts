/**
 * Backend API Client for PhishGuard Extension.
 * Handles cloud enrichment queries with offline fallback.
 */

import { DOMSignals, ScanResult, ScanVerdict } from './types';

export class BackendApiClient {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(baseUrl: string = 'http://localhost:8000', timeoutMs: number = 2500) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
  }

  /**
   * Request cloud threat enrichment for a URL.
   * If backend is offline or times out, returns null to allow seamless local fallback.
   */
  async scanUrl(
    url: string,
    deviceId?: string,
    domSignals?: DOMSignals
  ): Promise<ScanResult | null> {
    const endpoint = `${this.baseUrl}/api/v1/scan`;

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          device_id: deviceId,
          dom_signals: domSignals || null,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        console.warn(`[PhishGuard API] Backend returned HTTP ${response.status}`);
        return null;
      }

      const data = await response.json();

      return {
        url: data.url || url,
        domain: data.domain || '',
        verdict: (data.verdict as ScanVerdict) || 'UNKNOWN',
        score: typeof data.risk_score === 'number' ? data.risk_score : 0,
        confidence: typeof data.confidence === 'number' ? data.confidence : 0,
        evidence: (data.evidence || []).map((e: any) => ({
          id: e.id || e.rule_name,
          rule_name: e.rule_name,
          layer: e.layer,
          score_impact: e.score_impact,
          description: e.description,
          confidence: e.confidence,
          metadata: e.metadata || {},
        })),
        source: 'cloud',
        scanned_at: data.scanned_at || new Date().toISOString(),
        engine_version: data.engine_version || 'cloud-1.0.0',
      };
    } catch (err) {
      // Abort / offline / network failure -> safe fallback to local heuristics
      clearTimeout(timeoutId);
      console.debug('[PhishGuard API] Cloud scan unavailable, falling back to local detection:', err);
      return null;
    }
  }
}

export const apiClient = new BackendApiClient();
