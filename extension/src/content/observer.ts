/**
 * Privacy-Preserving Structural DOM Signal Extractor.
 * Inspects form action origins, password inputs, and hidden iframes.
 * STRICT PRIVACY GUARANTEE: Never inspects, extracts, or transmits form values, passwords, or cookies.
 */

import { DOMSignals } from '../shared/types';

const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

export class DOMSignalExtractor {
  /**
   * Extract structural security indicators from the DOM tree.
   */
  static extractSignals(
    doc: Document,
    loc: { origin: string; href: string }
  ): DOMSignals {
    let hasPasswordField = false;
    let hasLoginForm = false;
    let formActionOriginMismatch = false;
    let formActionIsIp = false;
    let primaryActionTarget: string | undefined = undefined;

    // 1. Password input detection
    const passwordInputs = doc.querySelectorAll('input[type="password"]');
    if (passwordInputs.length > 0) {
      hasPasswordField = true;
    }

    // 2. Form inspection
    const forms = doc.querySelectorAll('form');
    for (let i = 0; i < forms.length; i++) {
      const form = forms[i];
      const hasPasswordInForm = form.querySelector('input[type="password"]') !== null;
      const hasEmailOrUsername =
        form.querySelector('input[type="email"], input[name*="user" i], input[name*="login" i]') !== null;

      if (hasPasswordInForm || (hasEmailOrUsername && forms.length === 1)) {
        hasLoginForm = true;
      }

      // Action URL inspection
      const rawAction = form.getAttribute('action');
      if (rawAction && rawAction.trim() !== '' && rawAction.trim() !== '#') {
        try {
          const actionUrl = new URL(rawAction, loc.href);

          // Ignore javascript: or mailto:
          if (actionUrl.protocol === 'http:' || actionUrl.protocol === 'https:') {
            if (actionUrl.origin !== loc.origin) {
              formActionOriginMismatch = true;
              if (!primaryActionTarget) {
                primaryActionTarget = actionUrl.origin;
              }
            }

            if (IPV4_REGEX.test(actionUrl.hostname)) {
              formActionIsIp = true;
              if (!primaryActionTarget) {
                primaryActionTarget = actionUrl.origin;
              }
            }
          }
        } catch {
          // If action URL is unparseable, ignore
        }
      }
    }

    // 3. Hidden iframes detection
    let hiddenIframesCount = 0;
    const iframes = doc.querySelectorAll('iframe');
    for (let i = 0; i < iframes.length; i++) {
      const iframe = iframes[i];
      const style = iframe.style;
      const widthAttr = iframe.getAttribute('width');
      const heightAttr = iframe.getAttribute('height');
      const isHiddenAttr = iframe.hasAttribute('hidden');

      const isStyleHidden =
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.opacity === '0' ||
        style.width === '0px' ||
        style.height === '0px' ||
        style.width === '1px' ||
        style.height === '1px';

      const isAttrHidden =
        widthAttr === '0' ||
        heightAttr === '0' ||
        widthAttr === '1' ||
        heightAttr === '1';

      if (isHiddenAttr || isStyleHidden || isAttrHidden) {
        hiddenIframesCount++;
      }
    }

    // 4. External script ratio
    const scripts = doc.querySelectorAll('script[src]');
    let externalScriptCount = 0;
    for (let i = 0; i < scripts.length; i++) {
      const src = scripts[i].getAttribute('src');
      if (src) {
        try {
          const scriptUrl = new URL(src, loc.href);
          if (scriptUrl.origin !== loc.origin) {
            externalScriptCount++;
          }
        } catch {
          // Ignored
        }
      }
    }

    const externalResourcesRatio =
      scripts.length > 0 ? parseFloat((externalScriptCount / scripts.length).toFixed(2)) : 0.0;

    return {
      has_password_field: hasPasswordField,
      has_login_form: hasLoginForm,
      form_action_origin_mismatch: formActionOriginMismatch,
      form_action_is_ip: formActionIsIp,
      form_action_target: primaryActionTarget,
      hidden_iframes_count: hiddenIframesCount,
      external_resources_ratio: externalResourcesRatio,
    };
  }
}
