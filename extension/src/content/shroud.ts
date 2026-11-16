/**
 * Visual Holding Shroud and In-Page Warning Banner.
 * Injects a high-contrast, Shadow-DOM isolated banner over suspected credential-harvesting pages.
 */

export class WarningShroudManager {
  private static readonly CONTAINER_ID = 'phishguard-warning-shroud-root';

  /**
   * Check if the shroud is currently mounted in the page.
   */
  static isDisplayed(doc: Document = document): boolean {
    return doc.getElementById(this.CONTAINER_ID) !== null;
  }

  /**
   * Inject and display the warning shroud.
   */
  static showWarning(
    reason: string,
    details: string[] = [],
    doc: Document = document
  ): void {
    if (this.isDisplayed(doc)) {
      return;
    }

    const host = doc.createElement('div');
    host.id = this.CONTAINER_ID;
    host.style.position = 'fixed';
    host.style.top = '0';
    host.style.left = '0';
    host.style.width = '100vw';
    host.style.height = '100vh';
    host.style.zIndex = '2147483647'; // Maximum possible 32-bit signed z-index
    host.style.pointerEvents = 'auto';

    const shadow = host.attachShadow({ mode: 'open' });

    const style = doc.createElement('style');
    style.textContent = `
      :host {
        all: initial;
        display: block;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      }
      .backdrop {
        position: fixed;
        inset: 0;
        background: rgba(15, 23, 42, 0.85);
        backdrop-filter: blur(8px);
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
        box-sizing: border-box;
      }
      .card {
        background: #0f172a;
        border: 2px solid #ef4444;
        border-radius: 16px;
        max-width: 540px;
        width: 100%;
        padding: 32px;
        box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.25);
        color: #f8fafc;
        box-sizing: border-box;
      }
      .header {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
      }
      .badge {
        background: #ef4444;
        color: #ffffff;
        font-size: 11px;
        font-weight: 700;
        padding: 4px 8px;
        border-radius: 6px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
      }
      h2 {
        margin: 0;
        font-size: 20px;
        font-weight: 700;
        color: #fca5a5;
      }
      p.lead {
        margin: 0 0 16px 0;
        font-size: 15px;
        line-height: 1.5;
        color: #e2e8f0;
      }
      ul.details {
        margin: 0 0 24px 0;
        padding-left: 20px;
        color: #94a3b8;
        font-size: 13px;
        line-height: 1.6;
      }
      .actions {
        display: flex;
        gap: 12px;
        justify-content: flex-end;
      }
      button {
        cursor: pointer;
        font-weight: 600;
        font-size: 14px;
        padding: 10px 18px;
        border-radius: 8px;
        transition: all 0.15s ease;
      }
      button.primary {
        background: #ef4444;
        color: #ffffff;
        border: none;
      }
      button.primary:hover {
        background: #dc2626;
      }
      button.secondary {
        background: transparent;
        color: #94a3b8;
        border: 1px solid #334155;
      }
      button.secondary:hover {
        background: #1e293b;
        color: #f1f5f9;
      }
    `;

    const backdrop = doc.createElement('div');
    backdrop.className = 'backdrop';

    const card = doc.createElement('div');
    card.className = 'card';

    const header = doc.createElement('div');
    header.className = 'header';
    header.innerHTML = '<span class="badge">Security Warning</span><h2>Suspected Phishing Site</h2>';

    const lead = doc.createElement('p');
    lead.className = 'lead';
    lead.textContent = reason;

    card.appendChild(header);
    card.appendChild(lead);

    if (details.length > 0) {
      const list = doc.createElement('ul');
      list.className = 'details';
      for (const item of details) {
        const li = doc.createElement('li');
        li.textContent = item;
        list.appendChild(li);
      }
      card.appendChild(list);
    }

    const actions = doc.createElement('div');
    actions.className = 'actions';

    const secondaryBtn = doc.createElement('button');
    secondaryBtn.className = 'secondary';
    secondaryBtn.textContent = 'Proceed Anyway';
    secondaryBtn.onclick = () => this.dismiss(doc);

    const primaryBtn = doc.createElement('button');
    primaryBtn.className = 'primary';
    primaryBtn.textContent = 'Leave This Site (Safe)';
    primaryBtn.onclick = () => {
      if (typeof window !== 'undefined' && window.history && window.history.length > 1) {
        window.history.back();
      } else if (typeof window !== 'undefined') {
        window.location.href = 'about:blank';
      }
    };

    actions.appendChild(secondaryBtn);
    actions.appendChild(primaryBtn);
    card.appendChild(actions);

    backdrop.appendChild(card);
    shadow.appendChild(style);
    shadow.appendChild(backdrop);

    const targetContainer = doc.body || doc.documentElement;
    if (targetContainer) {
      targetContainer.appendChild(host);
    }
  }

  /**
   * Remove the warning shroud.
   */
  static dismiss(doc: Document = document): void {
    const el = doc.getElementById(this.CONTAINER_ID);
    if (el && el.parentNode) {
      el.parentNode.removeChild(el);
    }
  }
}
