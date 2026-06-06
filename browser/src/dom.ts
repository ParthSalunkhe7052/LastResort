import { Page } from 'playwright';

export interface BrowserElement {
  text: string;
  selector: string;
  type: string;
  href?: string;
  id?: string;
  name?: string;
  value?: string;
}

export interface BrowserForm {
  selector: string;
  action: string;
  method: string;
  inputs: BrowserElement[];
}

export interface PageContext {
  url: string;
  title: string;
  links: BrowserElement[];
  buttons: BrowserElement[];
  forms: BrowserForm[];
  localStorage?: Record<string, string>;
}

export async function scrapePageContext(page: Page): Promise<PageContext> {
  try {
    return await page.evaluate(() => {
      const getSelector = (el: Element): string => {
        if (el.id) return `#${CSS.escape(el.id)}`;
        
        const tag = el.tagName.toLowerCase();
        
        const name = el.getAttribute('name');
        if (name) return `${tag}[name="${CSS.escape(name)}"]`;
        
        const placeholder = el.getAttribute('placeholder');
        if (placeholder) return `${tag}[placeholder="${CSS.escape(placeholder)}"]`;
        
        const type = el.getAttribute('type');
        if (type && tag === 'input') return `${tag}[type="${CSS.escape(type)}"]`;

        const text = el.textContent?.trim();
        if (text && text.length > 0 && text.length < 30 && !text.includes('"') && !text.includes('\n')) {
          return `${tag}:has-text("${text}")`;
        }

        return tag;
      };

      const links: BrowserElement[] = Array.from(document.querySelectorAll('a')).map(el => ({
        text: el.textContent?.trim() || '',
        selector: getSelector(el),
        type: 'link',
        href: (el as HTMLAnchorElement).href,
        id: el.id,
        name: el.getAttribute('name') || undefined
      }));

      const buttons: BrowserElement[] = Array.from(document.querySelectorAll('button, input[type="button"], input[type="submit"], input[type="reset"]')).map(el => {
        const input = el as HTMLInputElement;
        return {
          text: el.textContent?.trim() || input.value || el.getAttribute('aria-label') || '',
          selector: getSelector(el),
          type: 'button',
          id: el.id,
          name: input.name || undefined,
          value: input.value || undefined
        };
      });

      const forms: BrowserForm[] = Array.from(document.querySelectorAll('form')).map(form => {
        const inputs: BrowserElement[] = Array.from(form.querySelectorAll('input, textarea, select')).map(el => {
          const input = el as HTMLInputElement;
          return {
            text: el.getAttribute('placeholder') || el.getAttribute('aria-label') || '',
            selector: getSelector(el),
            type: el.tagName.toLowerCase(),
            id: el.id,
            name: input.name || undefined,
            value: input.value || undefined
          };
        });

        return {
          selector: getSelector(form),
          action: (form as HTMLFormElement).action,
          method: (form as HTMLFormElement).method || 'GET',
          inputs
        };
      });

      // Extract Local Storage
      const storage: Record<string, string> = {};
      try {
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          if (key) {
            storage[key] = window.localStorage.getItem(key) || '';
          }
        }
      } catch (e) {
        console.error('Failed to access localStorage', e);
      }

      return {
        url: window.location.href,
        title: document.title,
        links: links.filter(l => l.href && !l.href.startsWith('javascript:')),
        buttons,
        forms,
        localStorage: storage
      };
    });
  } catch (error) {
    console.error(`[DOM SCRAPE] [ERROR] Failed to scrape page context:`, error);
    return {
      url: page.url(),
      title: '',
      links: [],
      buttons: [],
      forms: [],
      localStorage: {}
    };
  }
}

export async function getAXTreeString(page: Page): Promise<string> {
  try {
    // Open a Chrome DevTools Protocol session
    const client = await page.context().newCDPSession(page);
    await client.send('Accessibility.enable');
    const { nodes } = await client.send('Accessibility.getFullAXTree');
    await client.detach();

    if (!nodes || nodes.length === 0) return '';

    // Create lookup map of nodes
    const nodeMap = new Map<string, any>();
    for (const node of nodes) {
      nodeMap.set(node.nodeId, node);
    }

    // Identify the root node (usually the first node or node with role 'WebArea' / 'RootWebArea')
    const rootNode = nodes[0];
    if (!rootNode) return '';

    const getVal = (prop: any): string => {
      if (prop && prop.value) return String(prop.value);
      return '';
    };

    const formatNode = (nodeId: string, depth = 0): string => {
      const node = nodeMap.get(nodeId);
      if (!node) return '';

      const role = getVal(node.role);
      // Skip generic and presentational containers to keep the tree small and readable
      if (role === 'none' || role === 'GenericContainer' || role === 'ignored') {
        let result = '';
        if (node.childNodeIds) {
          for (const childId of node.childNodeIds) {
            result += formatNode(childId, depth);
          }
        }
        return result;
      }

      const name = getVal(node.name);
      const value = getVal(node.value);
      const description = getVal(node.description);

      const indentation = '  '.repeat(depth);
      let desc = `${indentation}[${role}`;
      if (name) {
        desc += ` "${name}"`;
      }
      if (value) {
        desc += ` value="${value}"`;
      }
      if (description) {
        desc += ` description="${description}"`;
      }
      desc += ']';

      let result = desc + '\n';
      if (node.childNodeIds) {
        for (const childId of node.childNodeIds) {
          result += formatNode(childId, depth + 1);
        }
      }
      return result;
    };

    return formatNode(rootNode.nodeId);
  } catch (err) {
    console.error('Failed to capture accessibility tree:', err);
    return '';
  }
}

export async function dismissPopups(page: Page): Promise<void> {
  try {
    const selectors = [
      'button[aria-label="Close Welcome Banner"]',
      'button:has-text("Dismiss")',
      'a:has-text("Dismiss")',
      '.close-dialog',
      'button:has-text("Got it")',
      'button:has-text("Accept Cookies")',
      'button:has-text("Accept all")',
      '#accept-choices',
      '.cc-dismiss',
      '.cc-btn.cc-dismiss'
    ];
    for (const selector of selectors) {
      try {
        const locator = page.locator(selector);
        if (await locator.count() > 0) {
          for (let i = 0; i < await locator.count(); i++) {
            const btn = locator.nth(i);
            if (await btn.isVisible()) {
              await btn.click({ timeout: 1500 }).catch(() => {});
              console.log(`[BROWSER] Auto-dismissed element matching: "${selector}"`);
            }
          }
        }
      } catch (e) {
        // ignore
      }
    }
  } catch (err) {
    // ignore
  }
}
