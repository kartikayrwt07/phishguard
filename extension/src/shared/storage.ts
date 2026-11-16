/**
 * Storage Manager for PhishGuard Chrome Extension.
 * Wraps chrome.storage.local with typed methods, TTL scan caching,
 * and automatic fallback for testing environments.
 */

import {
  AllowlistEntry,
  CacheEntry,
  DEFAULT_USER_SETTINGS,
  DeviceInfo,
  ScanResult,
  UserSettings,
} from './types';

const STORAGE_KEYS = {
  DEVICE_INFO: 'phishguard_device_info',
  SETTINGS: 'phishguard_settings',
  SCAN_CACHE: 'phishguard_scan_cache',
  ALLOWLIST: 'phishguard_allowlist',
} as const;

// Simple UUIDv4 generator for browser and test environments
function generateUUID(): string {
  if (typeof crypto !== 'undefined' && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

export class StorageManager {
  private inMemoryFallback: Map<string, unknown> = new Map();

  private isChromeStorageAvailable(): boolean {
    return (
      typeof chrome !== 'undefined' &&
      Boolean(chrome.storage) &&
      Boolean(chrome.storage.local)
    );
  }

  private async getRaw<T>(key: string): Promise<T | undefined> {
    if (this.isChromeStorageAvailable()) {
      return new Promise((resolve) => {
        chrome.storage.local.get([key], (result) => {
          resolve(result[key] as T | undefined);
        });
      });
    }
    return this.inMemoryFallback.get(key) as T | undefined;
  }

  private async setRaw<T>(key: string, value: T): Promise<void> {
    if (this.isChromeStorageAvailable()) {
      return new Promise((resolve) => {
        chrome.storage.local.set({ [key]: value }, () => {
          resolve();
        });
      });
    }
    this.inMemoryFallback.set(key, value);
  }

  private async removeRaw(key: string): Promise<void> {
    if (this.isChromeStorageAvailable()) {
      return new Promise((resolve) => {
        chrome.storage.local.remove([key], () => {
          resolve();
        });
      });
    }
    this.inMemoryFallback.delete(key);
  }

  /**
   * Get or generate unique device installation UUID.
   */
  async getDeviceInfo(currentVersion: string = '1.0.0'): Promise<DeviceInfo> {
    const existing = await this.getRaw<DeviceInfo>(STORAGE_KEYS.DEVICE_INFO);
    if (existing && existing.deviceId) {
      return existing;
    }

    const created: DeviceInfo = {
      deviceId: generateUUID(),
      extensionVersion: currentVersion,
      installedAt: new Date().toISOString(),
    };
    await this.setRaw(STORAGE_KEYS.DEVICE_INFO, created);
    return created;
  }

  /**
   * Retrieve user settings, merging with defaults.
   */
  async getSettings(): Promise<UserSettings> {
    const stored = await this.getRaw<Partial<UserSettings>>(STORAGE_KEYS.SETTINGS);
    return {
      ...DEFAULT_USER_SETTINGS,
      ...(stored || {}),
    };
  }

  /**
   * Update user settings.
   */
  async saveSettings(partial: Partial<UserSettings>): Promise<UserSettings> {
    const current = await this.getSettings();
    const updated: UserSettings = {
      ...current,
      ...partial,
    };
    await this.setRaw(STORAGE_KEYS.SETTINGS, updated);
    return updated;
  }

  /**
   * Retrieve cached scan result if present and within TTL.
   */
  async getScanCache(url: string): Promise<ScanResult | null> {
    const cacheMap =
      (await this.getRaw<Record<string, CacheEntry<ScanResult>>>(
        STORAGE_KEYS.SCAN_CACHE
      )) || {};

    const entry = cacheMap[url];
    if (!entry) {
      return null;
    }

    const now = Date.now();
    if (now >= entry.expiresAt) {
      // Expired entry: prune it
      delete cacheMap[url];
      await this.setRaw(STORAGE_KEYS.SCAN_CACHE, cacheMap);
      return null;
    }

    return entry.data;
  }

  /**
   * Save a scan result to cache with TTL.
   * Default TTL: 900 seconds (15 minutes).
   */
  async saveScanResult(
    result: ScanResult,
    ttlSeconds: number = 900
  ): Promise<void> {
    const cacheMap =
      (await this.getRaw<Record<string, CacheEntry<ScanResult>>>(
        STORAGE_KEYS.SCAN_CACHE
      )) || {};

    const now = Date.now();
    cacheMap[result.url] = {
      data: result,
      cachedAt: now,
      expiresAt: now + ttlSeconds * 1000,
    };

    // Prune oldest entries if cache exceeds 500 items
    const keys = Object.keys(cacheMap);
    if (keys.length > 500) {
      keys.sort((a, b) => cacheMap[a].expiresAt - cacheMap[b].expiresAt);
      const toDelete = keys.slice(0, 100);
      for (const k of toDelete) {
        delete cacheMap[k];
      }
    }

    await this.setRaw(STORAGE_KEYS.SCAN_CACHE, cacheMap);
  }

  /**
   * Clear all cached scan results.
   */
  async clearScanCache(): Promise<void> {
    await this.removeRaw(STORAGE_KEYS.SCAN_CACHE);
  }

  /**
   * Get user allowlisted domains.
   */
  async getAllowlist(): Promise<AllowlistEntry[]> {
    return (await this.getRaw<AllowlistEntry[]>(STORAGE_KEYS.ALLOWLIST)) || [];
  }

  /**
   * Add a domain to the user allowlist.
   */
  async addAllowlistDomain(
    domain: string,
    reason?: string
  ): Promise<AllowlistEntry[]> {
    const cleanDomain = domain.trim().toLowerCase();
    const current = await this.getAllowlist();

    if (current.some((e) => e.domain === cleanDomain)) {
      return current;
    }

    const updated: AllowlistEntry[] = [
      ...current,
      {
        domain: cleanDomain,
        added_at: new Date().toISOString(),
        reason,
      },
    ];

    await this.setRaw(STORAGE_KEYS.ALLOWLIST, updated);
    return updated;
  }

  /**
   * Remove a domain from the user allowlist.
   */
  async removeAllowlistDomain(domain: string): Promise<AllowlistEntry[]> {
    const cleanDomain = domain.trim().toLowerCase();
    const current = await this.getAllowlist();
    const updated = current.filter((e) => e.domain !== cleanDomain);
    await this.setRaw(STORAGE_KEYS.ALLOWLIST, updated);
    return updated;
  }

  /**
   * Check if a domain (or its parent domain) is allowlisted.
   */
  async isDomainAllowlisted(domain: string): Promise<boolean> {
    const clean = domain.trim().toLowerCase();
    const list = await this.getAllowlist();

    return list.some((entry) => {
      const allowed = entry.domain;
      return clean === allowed || clean.endsWith(`.${allowed}`);
    });
  }

  /**
   * Clear all storage (for testing or profile reset).
   */
  async clearAll(): Promise<void> {
    await this.removeRaw(STORAGE_KEYS.DEVICE_INFO);
    await this.removeRaw(STORAGE_KEYS.SETTINGS);
    await this.removeRaw(STORAGE_KEYS.SCAN_CACHE);
    await this.removeRaw(STORAGE_KEYS.ALLOWLIST);
    this.inMemoryFallback.clear();
  }
}

export const storageManager = new StorageManager();

