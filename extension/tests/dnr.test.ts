import { describe, it, expect, beforeEach } from 'vitest';
import { DNRRuleManager } from '../src/background/dnr';

describe('DNRRuleManager', () => {
  let dnr: DNRRuleManager;

  beforeEach(async () => {
    dnr = new DNRRuleManager();
    await dnr.clearAllRules();
  });

  it('registers a dynamic block rule for a malicious domain', async () => {
    const ruleId = await dnr.blockDomain('malicious-phish.xyz');
    expect(ruleId).toBeGreaterThanOrEqual(1000);

    const rules = await dnr.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0].id).toBe(ruleId);
    expect(rules[0].action.type).toBe('block');
    expect(rules[0].condition.urlFilter).toBe('||malicious-phish.xyz^');
  });

  it('registers a dynamic redirect rule when warning page is provided', async () => {
    const warningPage = 'chrome-extension://dummy-id/warning.html';
    const ruleId = await dnr.blockDomain('paypa1-scam.xyz', warningPage);

    const rules = await dnr.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0].id).toBe(ruleId);
    expect(rules[0].action.type).toBe('redirect');
    expect(rules[0].action.redirect?.url).toContain('warning.html?blocked_url=');
    expect(rules[0].action.redirect?.url).toContain(encodeURIComponent('http://paypa1-scam.xyz'));
  });

  it('removes dynamic rule by rule ID', async () => {
    const rule1 = await dnr.blockDomain('threat1.xyz');
    const rule2 = await dnr.blockDomain('threat2.xyz');

    let rules = await dnr.getRules();
    expect(rules.length).toBe(2);

    await dnr.removeRule(rule1);
    rules = await dnr.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0].id).toBe(rule2);
  });

  it('removes rules by domain name when domain is trusted or unblocked', async () => {
    await dnr.blockDomain('false-positive.com');
    await dnr.blockDomain('real-threat.com');

    let rules = await dnr.getRules();
    expect(rules.length).toBe(2);

    await dnr.removeRulesForDomain('false-positive.com');
    rules = await dnr.getRules();
    expect(rules.length).toBe(1);
    expect(rules[0].condition.urlFilter).toBe('||real-threat.com^');
  });

  it('clears all dynamic rules', async () => {
    await dnr.blockDomain('threat1.com');
    await dnr.blockDomain('threat2.com');
    await dnr.blockDomain('threat3.com');

    let rules = await dnr.getRules();
    expect(rules.length).toBe(3);

    await dnr.clearAllRules();
    rules = await dnr.getRules();
    expect(rules.length).toBe(0);
  });
});

