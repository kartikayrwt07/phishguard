import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { Window } from 'happy-dom';
import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import { WarningApp } from '../src/warning/index';
import { ScanResult } from '../src/shared/types';

describe('WarningApp Interstitial UI', () => {
  let happyWindow: Window;

  beforeEach(() => {
    // @ts-expect-error React act environment
    global.IS_REACT_ACT_ENVIRONMENT = true;
    happyWindow = new Window({ url: 'http://localhost/warning.html?blocked_url=http%3A%2F%2Fpaypa1-login.xyz' });
    // @ts-expect-error mock global window
    global.window = happyWindow;
    global.document = happyWindow.document as unknown as Document;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  const mockPhishingScan: ScanResult = {
    url: 'http://paypa1-login.xyz/account',
    domain: 'paypa1-login.xyz',
    verdict: 'PHISHING',
    score: 88,
    confidence: 0.95,
    source: 'local',
    engine_version: '1.0.0',
    scanned_at: new Date().toISOString(),
    evidence: [
      {
        id: 'brand_homoglyph',
        rule_name: 'BRAND_HOMOGLYPH_MATCH',
        layer: 'brand_impersonation',
        score_impact: 60,
        description: "Domain impersonates 'PayPal' using homoglyph or lookalike substitutions.",
        confidence: 0.95,
      },
      {
        id: 'suspicious_tld',
        rule_name: 'URL_HIGH_RISK_TLD',
        layer: 'url_analysis',
        score_impact: 15,
        description: "Top-level domain '.xyz' has high association with malicious campaigns.",
        confidence: 0.8,
      },
    ],
  };

  it('renders critical warning header, risk score, and target domain', () => {
    const html = renderToString(
      React.createElement(WarningApp, {
        initialBlockedUrl: 'http://paypa1-login.xyz/account',
        initialScanResult: mockPhishingScan,
      })
    );

    expect(html).toContain('Deceptive Destination Blocked');
    expect(html).toContain('paypa1-login.xyz');
    expect(html).toContain('High Risk Threat');
    expect(html).toContain('Risk Score: 88/100');
    expect(html).toContain('Confidence: 95%');
  });

  it('renders itemized explainable evidence with rule names and score impacts', () => {
    const html = renderToString(
      React.createElement(WarningApp, {
        initialBlockedUrl: 'http://paypa1-login.xyz/account',
        initialScanResult: mockPhishingScan,
      })
    );

    expect(html).toContain('BRAND_HOMOGLYPH_MATCH');
    expect(html).toContain('brand_impersonation');
    expect(html).toContain('+60 pts');
    expect(html).toContain('URL_HIGH_RISK_TLD');
    expect(html).toContain('+15 pts');
  });

  it('invokes onBack callback when Back to Safety button is triggered', () => {
    const onBackMock = vi.fn();
    const container = happyWindow.document.createElement('div');
    happyWindow.document.body.appendChild(container);

    // Using ReactDOM render in happy-dom
    const html = renderToString(
      React.createElement(WarningApp, {
        initialBlockedUrl: 'http://paypa1-login.xyz/account',
        initialScanResult: mockPhishingScan,
        onBack: onBackMock,
      })
    );

    container.innerHTML = html;
    const leaveBtn = container.querySelector('[data-testid="leave-site-btn"]');
    expect(leaveBtn).not.toBeNull();
    expect(leaveBtn?.textContent).toContain('Back to Safety (Recommended)');
  });

  it('falls back to local heuristic engine when no scan result is pre-loaded', () => {
    const targetUrl = 'http://paypa1-account-security.xyz/login.php';
    const html = renderToString(
      React.createElement(WarningApp, {
        initialBlockedUrl: targetUrl,
      })
    );

    expect(html).toContain('Deceptive Destination Blocked');
    expect(html).toContain('paypa1-account-security.xyz');
    // HeuristicEngine flagged PayPal homoglyph under brand_impersonation
    expect(html).toContain('HOMOGLYPH_MATCH');
    expect(html).toContain('brand_impersonation');
  });

  it('displays advanced security warning instructions when advanced options are shown', () => {
    // Testing the UI structure when showAdvanced is true
    const html = renderToString(
      React.createElement(WarningApp, {
        initialBlockedUrl: 'http://paypa1-login.xyz/account',
        initialScanResult: mockPhishingScan,
      })
    );

    expect(html).toContain('Advanced Options');
    expect(html).toContain('← Back to Safety (Recommended)');
  });

  it('handles clicking toggle advanced and bypass buttons', async () => {
    const onNavigateMock = vi.fn();
    const container = happyWindow.document.createElement('div');
    happyWindow.document.body.appendChild(container);
    const root = createRoot(container as unknown as HTMLElement);

    await act(async () => {
      root.render(
        React.createElement(WarningApp, {
          initialBlockedUrl: 'http://paypa1-login.xyz/account',
          initialScanResult: mockPhishingScan,
          onNavigate: onNavigateMock,
        })
      );
    });

    // Advanced panel initially not present
    expect(container.querySelector('[data-testid="advanced-panel"]')).toBeNull();

    // Click advanced toggle button
    const toggleBtn = container.querySelector('[data-testid="toggle-advanced-btn"]') as unknown as HTMLButtonElement;
    expect(toggleBtn).not.toBeNull();

    await act(async () => {
      toggleBtn.click();
    });

    // Advanced panel is now present
    const advancedPanel = container.querySelector('[data-testid="advanced-panel"]');
    expect(advancedPanel).not.toBeNull();

    // Click bypass once button
    const bypassBtn = container.querySelector('[data-testid="bypass-once-btn"]') as unknown as HTMLButtonElement;
    expect(bypassBtn).not.toBeNull();

    await act(async () => {
      bypassBtn.click();
    });

    expect(onNavigateMock).toHaveBeenCalledWith('http://paypa1-login.xyz/account');
  });

  it('handles clicking always trust domain button', async () => {
    const onNavigateMock = vi.fn();
    const container = happyWindow.document.createElement('div');
    happyWindow.document.body.appendChild(container);
    const root = createRoot(container as unknown as HTMLElement);

    await act(async () => {
      root.render(
        React.createElement(WarningApp, {
          initialBlockedUrl: 'http://paypa1-login.xyz/account',
          initialScanResult: mockPhishingScan,
          onNavigate: onNavigateMock,
        })
      );
    });

    // Toggle advanced
    const toggleBtn = container.querySelector('[data-testid="toggle-advanced-btn"]') as unknown as HTMLButtonElement;
    await act(async () => {
      toggleBtn.click();
    });

    // Click always trust button
    const trustBtn = container.querySelector('[data-testid="always-trust-btn"]') as unknown as HTMLButtonElement;
    expect(trustBtn).not.toBeNull();

    await act(async () => {
      trustBtn.click();
    });

    expect(onNavigateMock).toHaveBeenCalledWith('http://paypa1-login.xyz/account');
  });
});
