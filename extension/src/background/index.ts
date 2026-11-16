/**
 * PhishGuard Background Service Worker.
 * Manifest V3 entry point managing lifecycle, persistent storage,
 * tab navigation monitoring, typed message dispatching,
 * offline heuristic scoring (<15ms), and dynamic DNR rule management.
 */

import { storageManager } from '../shared/storage';
import {
  ExtensionMessage,
  MessageResponse,
} from '../shared/messages';
import { ScanResult, ScanVerdict } from '../shared/types';
import { BadgeManager } from './badge';
import { HeuristicEngine } from '../detection/heuristics';
import { dnrRuleManager } from './dnr';

const EXTENSION_VERSION = '1.0.0';

/**
 * Handle incoming extension messages from Popup, Content Scripts, or Options.
 */
async function handleMessage(
  message: ExtensionMessage,
  _sender: chrome.runtime.MessageSender
): Promise<MessageResponse<unknown>> {
  try {
    switch (message.type) {
      case 'PING':
        return {
          success: true,
          data: { type: 'PONG', timestamp: Date.now() },
        };

      case 'GET_DEVICE_INFO': {
        const info = await storageManager.getDeviceInfo(EXTENSION_VERSION);
        return { success: true, data: info };
      }

      case 'GET_SETTINGS': {
        const settings = await storageManager.getSettings();
        return { success: true, data: settings };
      }

      case 'UPDATE_SETTINGS': {
        const updated = await storageManager.saveSettings(message.payload);
        return { success: true, data: updated };
      }

      case 'GET_SCAN_CACHE': {
        const cached = await storageManager.getScanCache(message.payload.url);
        return { success: true, data: cached };
      }

      case 'GET_ALLOWLIST': {
        const list = await storageManager.getAllowlist();
        return { success: true, data: list };
      }

      case 'ADD_ALLOWLIST': {
        const updated = await storageManager.addAllowlistDomain(
          message.payload.domain,
          message.payload.reason
        );
        // Remove any active DNR blocking rule for this newly trusted domain
        await dnrRuleManager.removeRulesForDomain(message.payload.domain);
        return { success: true, data: { success: true, allowlist: updated } };
      }

      case 'REMOVE_ALLOWLIST': {
        const updated = await storageManager.removeAllowlistDomain(
          message.payload.domain
        );
        return { success: true, data: { success: true, allowlist: updated } };
      }

      case 'ANALYZE_URL': {
        const { url, tabId } = message.payload;
        const settings = await storageManager.getSettings();

        // 1. Check scan cache
        const cached = await storageManager.getScanCache(url);
        if (cached) {
          if (tabId) {
            await BadgeManager.updateBadge(tabId, cached.verdict);
          }
          return { success: true, data: cached };
        }

        // 2. Check user allowlist
        try {
          const urlObj = new URL(url);
          const isAllowed = await storageManager.isDomainAllowlisted(urlObj.hostname);
          if (isAllowed) {
            const allowResult: ScanResult = {
              url,
              domain: urlObj.hostname,
              verdict: 'SAFE',
              score: 0,
              confidence: 1.0,
              evidence: [
                {
                  id: 'allowlist_override',
                  rule_name: 'USER_ALLOWLIST',
                  layer: 'override',
                  score_impact: 0,
                  description: `Domain '${urlObj.hostname}' is on your trusted allowlist.`,
                  confidence: 1.0,
                },
              ],
              source: 'override',
              scanned_at: new Date().toISOString(),
              engine_version: '1.0.0',
            };
            await storageManager.saveScanResult(allowResult);
            if (tabId) {
              await BadgeManager.updateBadge(tabId, 'SAFE');
            }
            return { success: true, data: allowResult };
          }
        } catch {
          // If URL cannot be parsed by standard URL, let heuristic normalizer handle it
        }

        // 3. Run client-side offline heuristic analysis (<15ms)
        const result = HeuristicEngine.analyze(url, settings.sensitivityThreshold);

        // Update toolbar badge
        if (tabId) {
          await BadgeManager.updateBadge(tabId, result.verdict);
        }

        // Persist to scan cache
        await storageManager.saveScanResult(result);

        // 4. If confirmed threat and autoBlockEnabled, register DNR dynamic rule
        if (result.verdict === 'PHISHING' && settings.autoBlockEnabled && result.domain) {
          const warningUrl =
            typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL
              ? chrome.runtime.getURL('warning.html')
              : undefined;
          await dnrRuleManager.blockDomain(result.domain, warningUrl);
        }

        return { success: true, data: result };
      }

      case 'SUBMIT_DOM_SIGNALS': {
        const { url, signals, tabId } = message.payload;
        const settings = await storageManager.getSettings();

        // Check if domain is allowlisted
        try {
          const urlObj = new URL(url);
          const isAllowed = await storageManager.isDomainAllowlisted(urlObj.hostname);
          if (isAllowed) {
            return {
              success: true,
              data: { verdict: 'SAFE', score: 0, reason: 'Domain is allowlisted' },
            };
          }
        } catch {
          // Ignored
        }

        // Get base scan result from cache or heuristic analysis
        let result = await storageManager.getScanCache(url);
        if (!result) {
          result = HeuristicEngine.analyze(url, settings.sensitivityThreshold);
        }

        const evidence = [...result.evidence];
        let addedScore = 0;

        // 1. Cross-origin credential form submission
        if (signals.form_action_origin_mismatch && signals.has_login_form) {
          addedScore += 40;
          evidence.push({
            id: 'dom_action_mismatch',
            rule_name: 'FORM_ACTION_ORIGIN_MISMATCH',
            layer: 'dom_indicators',
            score_impact: 40,
            description: `Login form submits credentials across origins to '${signals.form_action_target || 'external host'}'.`,
            confidence: 0.95,
          });
        }

        // 2. IP destination form action
        if (signals.form_action_is_ip) {
          addedScore += 35;
          evidence.push({
            id: 'dom_ip_action',
            rule_name: 'FORM_ACTION_IP_DESTINATION',
            layer: 'dom_indicators',
            score_impact: 35,
            description: `Credential form action points directly to an IP address '${signals.form_action_target}'.`,
            confidence: 0.9,
          });
        }

        // 3. Hidden iframes
        if (signals.hidden_iframes_count > 0) {
          addedScore += 15;
          evidence.push({
            id: 'dom_hidden_iframes',
            rule_name: 'HIDDEN_IFRAMES_DETECTED',
            layer: 'dom_indicators',
            score_impact: 15,
            description: `Page embeds ${signals.hidden_iframes_count} hidden or zero-dimension iframe(s).`,
            confidence: 0.75,
          });
        }

        const finalScore = Math.min(100, Math.max(0, result.score + addedScore));
        let finalVerdict: ScanVerdict = result.verdict;

        if (finalScore >= 70) {
          finalVerdict = 'PHISHING';
        } else if (finalScore >= settings.sensitivityThreshold) {
          finalVerdict = 'SUSPICIOUS';
        }

        const updatedResult: ScanResult = {
          ...result,
          score: finalScore,
          verdict: finalVerdict,
          evidence,
          scanned_at: new Date().toISOString(),
        };

        // Update cache and toolbar badge
        await storageManager.saveScanResult(updatedResult);
        if (tabId) {
          await BadgeManager.updateBadge(tabId, finalVerdict);
        }

        // Register DNR auto-block if upgraded to PHISHING
        if (finalVerdict === 'PHISHING' && settings.autoBlockEnabled && updatedResult.domain) {
          const warningUrl =
            typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.getURL
              ? chrome.runtime.getURL('warning.html')
              : undefined;
          await dnrRuleManager.blockDomain(updatedResult.domain, warningUrl);
        }

        return {
          success: true,
          data: updatedResult,
        };
      }

      default:
        return {
          success: false,
          error: `Unrecognized message type: ${(message as { type: string }).type}`,
        };
    }
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ---------------------------------------------------------------------------
// Manifest V3 Top-Level Event Listeners
// ---------------------------------------------------------------------------

if (typeof chrome !== 'undefined' && chrome.runtime) {
  // 1. Install & Update Lifecycle
  chrome.runtime.onInstalled.addListener(async (details) => {
    console.info(`[PhishGuard] Extension installed/updated: ${details.reason}`);
    await storageManager.getDeviceInfo(EXTENSION_VERSION);
    await storageManager.getSettings();
  });

  // 2. Service Worker Startup
  chrome.runtime.onStartup.addListener(async () => {
    console.info('[PhishGuard] Background service worker resumed on startup.');
  });

  // 3. Typed Message Bus Listener
  chrome.runtime.onMessage.addListener(
    (
      message: ExtensionMessage,
      sender: chrome.runtime.MessageSender,
      sendResponse: (response: MessageResponse<unknown>) => void
    ) => {
      handleMessage(message, sender)
        .then((resp) => sendResponse(resp))
        .catch((err) =>
          sendResponse({
            success: false,
            error: err instanceof Error ? err.message : String(err),
          })
        );
      return true; // Keep message channel open for asynchronous sendResponse
    }
  );

  // 4. Tab Navigation Monitoring
  if (chrome.tabs && chrome.tabs.onUpdated) {
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (changeInfo.status === 'loading' && tab.url) {
        if (!tab.url.startsWith('http://') && !tab.url.startsWith('https://')) {
          await BadgeManager.clearBadge(tabId);
          return;
        }

        // Check cache first
        const cached = await storageManager.getScanCache(tab.url);
        if (cached) {
          await BadgeManager.updateBadge(tabId, cached.verdict);
          return;
        }

        // Quick offline heuristic scan to set badge immediately
        const settings = await storageManager.getSettings();
        const fastResult = HeuristicEngine.analyze(tab.url, settings.sensitivityThreshold);
        await BadgeManager.updateBadge(tabId, fastResult.verdict);
      }
    });
  }
}

export { handleMessage };
