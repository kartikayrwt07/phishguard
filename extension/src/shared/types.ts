/**
 * Core type definitions for PhishGuard Chrome Extension.
 */

export type ScanVerdict = 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'UNKNOWN';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface ScanEvidenceItem {
  id: string;
  rule_name: string;
  layer: string;
  score_impact: number;
  description: string;
  confidence: number;
  metadata?: Record<string, unknown>;
}

export interface ScanResult {
  url: string;
  domain: string;
  verdict: ScanVerdict;
  score: number; // 0 to 100
  confidence: number; // 0 to 1
  evidence: ScanEvidenceItem[];
  source: 'local' | 'cloud' | 'override';
  scanned_at: string; // ISO 8601 UTC
  engine_version: string;
}

export interface DOMSignals {
  has_password_field: boolean;
  has_login_form: boolean;
  form_action_origin_mismatch: boolean;
  form_action_is_ip: boolean;
  form_action_target?: string;
  hidden_iframes_count: number;
  external_resources_ratio: number;
}

export interface UserSettings {
  sensitivityThreshold: number; // default 50
  cloudEnrichmentEnabled: boolean; // default true
  autoBlockEnabled: boolean; // default true
  showWarningBanner: boolean; // default true
  telemetryOptIn: boolean; // default false
  backendApiUrl: string; // default http://localhost:8000
}

export const DEFAULT_USER_SETTINGS: UserSettings = {
  sensitivityThreshold: 50,
  cloudEnrichmentEnabled: true,
  autoBlockEnabled: true,
  showWarningBanner: true,
  telemetryOptIn: false,
  backendApiUrl: 'http://localhost:8000',
};

export interface AllowlistEntry {
  domain: string;
  added_at: string;
  reason?: string;
}

export interface DeviceInfo {
  deviceId: string;
  extensionVersion: string;
  installedAt: string;
}

export interface CacheEntry<T> {
  data: T;
  cachedAt: number; // unix timestamp ms
  expiresAt: number; // unix timestamp ms
}

