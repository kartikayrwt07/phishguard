/**
 * Action Badge Manager for PhishGuard Chrome Extension.
 * Updates the extension toolbar badge color and text according to the current tab's security verdict.
 */

import { ScanVerdict } from '../shared/types';

export class BadgeManager {
  private static readonly COLORS: Record<ScanVerdict, string> = {
    SAFE: '#22c55e',       // Emerald green
    SUSPICIOUS: '#eab308', // Amber yellow
    PHISHING: '#ef4444',   // Bright red
    UNKNOWN: '#94a3b8',    // Slate gray
  };

  private static readonly TEXTS: Record<ScanVerdict, string> = {
    SAFE: '',
    SUSPICIOUS: 'WARN',
    PHISHING: '!',
    UNKNOWN: '',
  };

  /**
   * Update the badge for a specific tab.
   */
  static async updateBadge(tabId: number, verdict: ScanVerdict): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) {
      return;
    }

    const text = this.TEXTS[verdict] || '';
    const color = this.COLORS[verdict] || this.COLORS.UNKNOWN;

    try {
      await chrome.action.setBadgeText({ tabId, text });
      await chrome.action.setBadgeBackgroundColor({ tabId, color });
    } catch {
      // Tab may have closed before badge could be set
    }
  }

  /**
   * Clear the badge on a specific tab.
   */
  static async clearBadge(tabId: number): Promise<void> {
    if (typeof chrome === 'undefined' || !chrome.action) {
      return;
    }

    try {
      await chrome.action.setBadgeText({ tabId, text: '' });
    } catch {
      // Ignored
    }
  }
}

