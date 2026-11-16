/**
 * DeclarativeNetRequest (DNR) Dynamic Rule Manager.
 * Synchronously blocks or redirects confirmed threat destinations before HTTP requests proceed.
 */

export interface DNRRule {
  id: number;
  priority: number;
  action: {
    type: 'block' | 'redirect';
    redirect?: {
      url?: string;
      extensionPath?: string;
    };
  };
  condition: {
    urlFilter: string;
    resourceTypes: chrome.declarativeNetRequest.ResourceType[];
  };
}

export class DNRRuleManager {
  private inMemoryRules: Map<number, DNRRule> = new Map();
  private nextRuleId: number = 1000;

  private isDnrAvailable(): boolean {
    return (
      typeof chrome !== 'undefined' &&
      Boolean(chrome.declarativeNetRequest) &&
      Boolean(chrome.declarativeNetRequest.updateDynamicRules)
    );
  }

  /**
   * Retrieve all currently active dynamic rules.
   */
  async getRules(): Promise<DNRRule[]> {
    if (this.isDnrAvailable()) {
      return new Promise((resolve) => {
        chrome.declarativeNetRequest.getDynamicRules((rules) => {
          resolve(rules as DNRRule[]);
        });
      });
    }
    return Array.from(this.inMemoryRules.values());
  }

  /**
   * Register a dynamic synchronous redirect or block rule for a confirmed threat domain.
   */
  async blockDomain(domain: string, warningPageUrl?: string): Promise<number> {
    const cleanDomain = domain.trim().toLowerCase();
    const ruleId = this.nextRuleId++;

    const action: DNRRule['action'] = warningPageUrl
      ? {
          type: 'redirect',
          redirect: {
            url: `${warningPageUrl}?blocked_url=${encodeURIComponent(`http://${cleanDomain}`)}`,
          },
        }
      : {
          type: 'block',
        };

    const newRule: DNRRule = {
      id: ruleId,
      priority: 1,
      action,
      condition: {
        urlFilter: `||${cleanDomain}^`,
        resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
      },
    };

    if (this.isDnrAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.declarativeNetRequest.updateDynamicRules(
          {
            addRules: [newRule as chrome.declarativeNetRequest.Rule],
          },
          () => {
            const err = chrome.runtime.lastError;
            if (err) {
              reject(new Error(err.message));
            } else {
              resolve(ruleId);
            }
          }
        );
      });
    }

    this.inMemoryRules.set(ruleId, newRule);
    return ruleId;
  }

  /**
   * Remove a dynamic rule by its integer ID.
   */
  async removeRule(ruleId: number): Promise<void> {
    if (this.isDnrAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.declarativeNetRequest.updateDynamicRules(
          {
            removeRuleIds: [ruleId],
          },
          () => {
            const err = chrome.runtime.lastError;
            if (err) {
              reject(new Error(err.message));
            } else {
              resolve();
            }
          }
        );
      });
    }
    this.inMemoryRules.delete(ruleId);
  }

  /**
   * Remove any active rules targeting a specific domain (e.g. after domain is allowlisted).
   */
  async removeRulesForDomain(domain: string): Promise<void> {
    const rules = await this.getRules();
    const cleanDomain = domain.trim().toLowerCase();
    const targetFilter = `||${cleanDomain}^`;

    const toRemove = rules
      .filter((r) => r.condition.urlFilter === targetFilter)
      .map((r) => r.id);

    if (toRemove.length === 0) return;

    if (this.isDnrAvailable()) {
      return new Promise((resolve, reject) => {
        chrome.declarativeNetRequest.updateDynamicRules(
          {
            removeRuleIds: toRemove,
          },
          () => {
            const err = chrome.runtime.lastError;
            if (err) {
              reject(new Error(err.message));
            } else {
              resolve();
            }
          }
        );
      });
    }

    for (const id of toRemove) {
      this.inMemoryRules.delete(id);
    }
  }

  /**
   * Clear all dynamic rules.
   */
  async clearAllRules(): Promise<void> {
    const rules = await this.getRules();
    const ids = rules.map((r) => r.id);
    if (ids.length === 0) return;

    if (this.isDnrAvailable()) {
      return new Promise((resolve) => {
        chrome.declarativeNetRequest.updateDynamicRules(
          {
            removeRuleIds: ids,
          },
          () => resolve()
        );
      });
    }
    this.inMemoryRules.clear();
  }
}

export const dnrRuleManager = new DNRRuleManager();

