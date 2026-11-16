/**
 * PhishGuard Content Script.
 * Runs in the context of visited web pages to inspect structural DOM indicators
 * and trigger visual holding warning shrouds when credential harvesting is detected.
 * STRICT PRIVACY GUARANTEE: Never collects, stores, or transmits input values, passwords, or cookies.
 */

import { sendMessageToBackground } from '../shared/messages';
import { ScanResult } from '../shared/types';
import { DOMSignalExtractor } from './observer';
import { WarningShroudManager } from './shroud';

let hasEvaluated = false;
let mutationTimeout: number | undefined = undefined;

/**
 * Scan current DOM and notify background service worker if structural indicators are found.
 */
async function analyzePageDOM(): Promise<void> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return;
  }

  // Skip about:blank, data: or chrome-extension: pages
  if (!window.location.protocol.startsWith('http')) {
    return;
  }

  const signals = DOMSignalExtractor.extractSignals(document, window.location);

  // If relevant structural signals are present, submit to service worker
  const isRelevant =
    signals.has_password_field ||
    signals.has_login_form ||
    signals.form_action_origin_mismatch ||
    signals.form_action_is_ip ||
    signals.hidden_iframes_count > 0;

  if (!isRelevant) {
    return;
  }

  try {
    const response = await sendMessageToBackground<ScanResult>({
      type: 'SUBMIT_DOM_SIGNALS',
      payload: {
        url: window.location.href,
        signals,
      },
    });

    if (response.success && response.data) {
      const result = response.data;

      // Trigger holding shroud if page is classified as PHISHING or has active credential harvesting mismatch
      if (
        result.verdict === 'PHISHING' ||
        (result.verdict === 'SUSPICIOUS' && (signals.form_action_origin_mismatch || signals.form_action_is_ip))
      ) {
        const reason = signals.form_action_origin_mismatch
          ? `This page contains a credential form submitting to an external host: ${signals.form_action_target || 'untrusted origin'}.`
          : signals.form_action_is_ip
          ? `This page submits credentials directly to an unprotected IP address: ${signals.form_action_target}.`
          : `PhishGuard has detected strong phishing indicators on this page (risk score: ${result.score}/100).`;

        const details = result.evidence.map((e) => e.description);
        WarningShroudManager.showWarning(reason, details, document);
      }
    }
  } catch (err) {
    console.debug('[PhishGuard] DOM signal reporting skipped:', err);
  }
}

function initContentScript(): void {
  // 1. Initial DOM check
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      if (!hasEvaluated) {
        hasEvaluated = true;
        analyzePageDOM();
      }
    });
  } else {
    hasEvaluated = true;
    analyzePageDOM();
  }

  // 2. Debounced MutationObserver for single-page applications / dynamic login modals
  const observer = new MutationObserver(() => {
    if (mutationTimeout) {
      clearTimeout(mutationTimeout);
    }
    mutationTimeout = window.setTimeout(() => {
      analyzePageDOM();
    }, 400);
  });

  if (document.body) {
    observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  } else {
    document.addEventListener('DOMContentLoaded', () => {
      if (document.body) {
        observer.observe(document.body, {
          childList: true,
          subtree: true,
        });
      }
    });
  }
}

initContentScript();

export { analyzePageDOM, DOMSignalExtractor, WarningShroudManager };
