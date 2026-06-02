import { chromium, Page } from 'playwright';
import { NetworkCapture, DiscoveredRequest } from './capture';
import { takeScreenshot } from './screenshot';
import * as url from 'url';

export interface CrawlResult {
  endpoints: Array<{ method: string; url: string; source: string }>;
  screenshots: Array<{ url: string; path: string }>;
}

export async function runBrowserCrawl(
  scanId: string,
  targetUrl: string,
  proxyPort?: number,
  maxDepth: number = 3
): Promise<CrawlResult> {
  const parsedTarget = url.parse(targetUrl);
  const targetHost = parsedTarget.host;
  
  if (!targetHost) {
    throw new Error(`Invalid target URL: ${targetUrl}`);
  }

  console.log(`[BROWSER CRAWLER] Starting crawl for ${targetUrl} (Proxy port: ${proxyPort})`);

  // Launch Playwright Chromium
  const browser = await chromium.launch({
    headless: true,
    args: [
      '--ignore-certificate-errors',
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ],
    proxy: proxyPort ? { server: `http://127.0.0.1:${proxyPort}` } : undefined
  });

  const context = await browser.newContext({
    extraHTTPHeaders: {
      'X-LastResort-Scan-ID': scanId,
    },
    userAgent: 'LastResort-BrowserCrawler/0.1.0',
    ignoreHTTPSErrors: true
  });

  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 1 }];
  const discoveredEndpoints: Map<string, { method: string; url: string; source: string }> = new Map();
  const screenshots: Array<{ url: string; path: string }> = [];

  const addEndpoint = (method: string, urlStr: string, source: string) => {
    // Normalize URL
    try {
      const u = new URL(urlStr);
      // Remove hash and trailing slash to deduplicate
      u.hash = '';
      const normalized = u.toString();
      const key = `${method}:${normalized}`;
      if (!discoveredEndpoints.has(key)) {
        discoveredEndpoints.set(key, { method, url: normalized, source });
      }
    } catch {
      // Ignore invalid URLs
    }
  };

  try {
    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;

      const { url: currentUrl, depth } = current;

      // Normalize current URL for checking visited
      let normalizedCurrentUrl = currentUrl;
      try {
        const u = new URL(currentUrl);
        u.hash = '';
        normalizedCurrentUrl = u.toString();
      } catch {}

      if (visited.has(normalizedCurrentUrl)) {
        continue;
      }
      visited.add(normalizedCurrentUrl);

      if (depth > maxDepth) {
        continue;
      }

      console.log(`[BROWSER CRAWLER] Depth ${depth} - Navigating to: ${currentUrl}`);

      const page = await context.newPage();
      const capture = new NetworkCapture(page);

      try {
        // Navigate and wait for page to load or idle
        await page.goto(currentUrl, { waitUntil: 'load', timeout: 15000 });
        
        // Let any SPA javascript run/fetch data
        await page.waitForTimeout(2000);

        // Take a screenshot as evidence
        const screenshotPath = await takeScreenshot(page, scanId, currentUrl);
        if (screenshotPath) {
          screenshots.push({ url: currentUrl, path: screenshotPath });
        }

        // Add the current URL as a GET endpoint
        addEndpoint('GET', currentUrl, 'browser_crawl');

        // Extract anchor links
        const links = await page.evaluate(() => {
          const elements = Array.from(document.querySelectorAll('a[href]'));
          return elements.map(el => (el as HTMLAnchorElement).href);
        });

        // Extract form actions
        const forms = await page.evaluate(() => {
          const elements = Array.from(document.querySelectorAll('form[action]'));
          return elements.map(el => {
            const form = el as HTMLFormElement;
            return {
              action: form.action,
              method: form.method || 'GET'
            };
          });
        });

        // Add form endpoints
        for (const form of forms) {
          if (form.action) {
            addEndpoint(form.method.toUpperCase(), form.action, 'browser_form');
            
            // Queue form action if it matches scope
            try {
              const u = new URL(form.action);
              if (u.host === targetHost && !visited.has(u.toString()) && depth < maxDepth) {
                queue.push({ url: form.action, depth: depth + 1 });
              }
            } catch {}
          }
        }

        // Extract and process any network requests captured (XHR, fetch, etc.)
        const captured = capture.getCapturedRequests();
        for (const req of captured) {
          try {
            const u = new URL(req.url);
            if (u.host === targetHost) {
              addEndpoint(req.method, req.url, `browser_${req.resourceType}`);
            }
          } catch {}
        }

        // Process found anchor links
        for (const link of links) {
          try {
            const u = new URL(link);
            // Only follow links within the scope (same host)
            if (u.host === targetHost) {
              const cleanedUrl = u.origin + u.pathname + u.search;
              addEndpoint('GET', cleanedUrl, 'browser_link');
              
              if (!visited.has(cleanedUrl) && depth < maxDepth) {
                queue.push({ url: cleanedUrl, depth: depth + 1 });
              }
            }
          } catch {
            // Ignore invalid URLs
          }
        }

      } catch (err) {
        console.error(`[BROWSER CRAWLER] [ERROR] Failed to crawl page ${currentUrl}:`, err);
      } finally {
        await page.close();
      }
    }
  } finally {
    await context.close();
    await browser.close();
  }

  return {
    endpoints: Array.from(discoveredEndpoints.values()),
    screenshots
  };
}
