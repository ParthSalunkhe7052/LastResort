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

      return {
        url: window.location.href,
        title: document.title,
        links: links.filter(l => l.href && !l.href.startsWith('javascript:')),
        buttons,
        forms
      };
    });
  } catch (error) {
    console.error(`[DOM SCRAPE] [ERROR] Failed to scrape page context:`, error);
    return {
      url: page.url(),
      title: '',
      links: [],
      buttons: [],
      forms: []
    };
  }
}
