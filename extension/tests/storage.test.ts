import { describe, it, expect, beforeEach } from 'vitest';
import { StorageManager } from '../src/shared/storage';
import { DEFAULT_USER_SETTINGS, ScanResult } from '../src/shared/types';

describe('StorageManager', () => {
  let storage: StorageManager;

  beforeEach(async () => {
    storage = new StorageManager();
    await storage.clearAll();
  });

  it('initializes default settings when storage is empty', async () => {
    const settings = await storage.getSettings();
    expect(settings).toEqual(DEFAULT_USER_SETTINGS);
    expect(settings.sensitivityThreshold).toBe(50);
    expect(settings.cloudEnrichmentEnabled).toBe(true);
    expect(settings.autoBlockEnabled).toBe(true);
  });

  it('persists and updates partial user settings', async () => {
    const updated = await storage.saveSettings({
      sensitivityThreshold: 75,
      autoBlockEnabled: false,
    });

    expect(updated.sensitivityThreshold).toBe(75);
    expect(updated.autoBlockEnabled).toBe(false);
    expect(updated.cloudEnrichmentEnabled).toBe(true); // preserved

    const reloaded = await storage.getSettings();
    expect(reloaded.sensitivityThreshold).toBe(75);
    expect(reloaded.autoBlockEnabled).toBe(false);
  });

  it('generates a stable device installation UUID', async () => {
    const info1 = await storage.getDeviceInfo('1.0.0');
    expect(info1.deviceId).toBeDefined();
    expect(info1.deviceId.length).toBeGreaterThan(10);
    expect(info1.extensionVersion).toBe('1.0.0');

    // Subsequent retrieval must return the identical deviceId
    const info2 = await storage.getDeviceInfo('1.0.0');
    expect(info2.deviceId).toBe(info1.deviceId);
  });

  it('stores and retrieves cached scan results within TTL', async () => {
    const mockScan: ScanResult = {
      url: 'https://test-site.example.com/login',
      domain: 'test-site.example.com',
      verdict: 'SAFE',
      score: 12.5,
      confidence: 0.95,
      evidence: [],
      source: 'local',
      scanned_at: new Date().toISOString(),
      engine_version: '1.0.0',
    };

    await storage.saveScanResult(mockScan, 300); // 5 min TTL
    const cached = await storage.getScanCache('https://test-site.example.com/login');

    expect(cached).not.toBeNull();
    expect(cached?.verdict).toBe('SAFE');
    expect(cached?.score).toBe(12.5);
  });

  it('evicts cached scan results once TTL expires', async () => {
    const mockScan: ScanResult = {
      url: 'https://ephemeral-site.example.com',
      domain: 'ephemeral-site.example.com',
      verdict: 'SUSPICIOUS',
      score: 65,
      confidence: 0.8,
      evidence: [],
      source: 'local',
      scanned_at: new Date().toISOString(),
      engine_version: '1.0.0',
    };

    // Store with 0-second TTL (instant expiration)
    await storage.saveScanResult(mockScan, -1);
    const cached = await storage.getScanCache('https://ephemeral-site.example.com');

    expect(cached).toBeNull();
  });

  it('manages user allowlist additions, removals, and subdomains', async () => {
    expect(await storage.getAllowlist()).toEqual([]);

    await storage.addAllowlistDomain('paypal.com', 'Trusted payment provider');
    let list = await storage.getAllowlist();
    expect(list.length).toBe(1);
    expect(list[0].domain).toBe('paypal.com');

    // Check exact domain and subdomain matching
    expect(await storage.isDomainAllowlisted('paypal.com')).toBe(true);
    expect(await storage.isDomainAllowlisted('accounts.paypal.com')).toBe(true);
    expect(await storage.isDomainAllowlisted('evil-paypal.com')).toBe(false);

    // Remove domain
    list = await storage.removeAllowlistDomain('paypal.com');
    expect(list.length).toBe(0);
    expect(await storage.isDomainAllowlisted('paypal.com')).toBe(false);
  });
});

