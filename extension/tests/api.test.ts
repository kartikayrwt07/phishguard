import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { BackendApiClient } from '../src/shared/api';
import { DOMSignals } from '../src/shared/types';

describe('BackendApiClient', () => {
  let client: BackendApiClient;
  const originalFetch = globalThis.fetch;

  beforeEach(() => {
    client = new BackendApiClient('http://localhost:8000', 500);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('maps successful backend scan responses into ScanResult', async () => {
    const mockResponse = {
      scan_id: '11111111-2222-3333-4444-555555555555',
      url: 'http://paypa1-fake.xyz',
      normalized_url: 'http://paypa1-fake.xyz/',
      domain: 'paypa1-fake.xyz',
      verdict: 'PHISHING',
      risk_score: 85,
      confidence: 0.95,
      evidence: [
        {
          id: 'homoglyph_1',
          rule_name: 'HOMOGLYPH_MATCH',
          layer: 'brand_impersonation',
          score_impact: 55,
          description: 'Uses homoglyphs mimicking brand paypal.',
          confidence: 0.95,
        },
      ],
      threat_sources: ['urlhaus'],
      scan_duration_ms: 120,
      scanned_at: '2026-11-14T08:00:00Z',
      engine_version: '1.0.0',
    };

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockResponse,
    } as unknown as Response);

    const domSignals: DOMSignals = {
      has_password_field: true,
      has_login_form: true,
      form_action_origin_mismatch: false,
      form_action_is_ip: false,
      hidden_iframes_count: 0,
      external_resources_ratio: 0.1,
    };

    const result = await client.scanUrl('http://paypa1-fake.xyz', 'test-device-uuid', domSignals);

    expect(result).not.toBeNull();
    expect(result?.verdict).toBe('PHISHING');
    expect(result?.score).toBe(85);
    expect(result?.source).toBe('cloud');
    expect(result?.evidence.length).toBe(1);
    expect(result?.evidence[0].rule_name).toBe('HOMOGLYPH_MATCH');
  });

  it('provides safe offline resilience returning null when backend is unreachable', async () => {
    // Simulate connection refused / offline
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));

    const result = await client.scanUrl('http://example.com');
    expect(result).toBeNull();
  });

  it('returns null on backend 500 error without throwing exceptions', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 500,
      statusText: 'Internal Server Error',
    } as unknown as Response);

    const result = await client.scanUrl('http://example.com');
    expect(result).toBeNull();
  });
});
