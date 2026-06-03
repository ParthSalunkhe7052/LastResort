import { chromium, Page } from 'playwright';
import { NetworkCapture } from './capture';
import { takeScreenshot } from './screenshot';
import * as url from 'url';

export interface CrawlResult {
  endpoints: Array<{ method: string; url: string; source: string }>;
  screenshots: Array<{ url: string; path: string }>;
}

// Push scan logs and screenshots back to Go API server
async function sendScanEvent(scanId: string, eventType: string, data: any) {
  try {
    await fetch('http://127.0.0.1:8443/api/v1/scan/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, event_type: eventType, data })
    });
  } catch (err) {
    console.error(`[BROWSER CRAWLER] Failed to push event ${eventType}:`, err);
  }
}

// Stream Base64 frames of Playwright active actions to React UI
async function streamPageScreenshot(page: Page, scanId: string) {
  try {
    const buffer = await page.screenshot({ type: 'png' });
    const base64 = buffer.toString('base64');
    await sendScanEvent(scanId, 'browser.screenshot', { image: `data:image/png;base64,${base64}` });
  } catch (err) {
    // Ignore screenshot errors during fast navigation/closing
  }
}

function isInCrawlScope(urlStr: string, seedUrl: string, targetHost: string): boolean {
  try {
    const u = new URL(urlStr);
    const s = new URL(seedUrl);
    
    if (u.host !== targetHost) {
      return false;
    }

    // Restrict path-prefix if seed has a specific sub-path (like /www-project-juice-shop/)
    let sCtx = s.pathname;
    if (sCtx && sCtx !== '/') {
      if (!sCtx.endsWith('/')) {
        sCtx += '/';
      }
      let uPath = u.pathname;
      if (!uPath.endsWith('/')) {
        uPath += '/';
      }
      return uPath.startsWith(sCtx);
    }
    
    return true;
  } catch {
    return false;
  }
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

  const logMessage = `[BROWSER CRAWLER] Starting crawl for ${targetUrl} (Proxy port: ${proxyPort})`;
  console.log(logMessage);
  await sendScanEvent(scanId, 'log.info', { message: logMessage });

  // Launch Playwright Chromium
  const browser = await chromium.launch({
    headless: false,
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
    try {
      const u = new URL(urlStr);
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

  // Reuse a single tab throughout the crawl to avoid reloads and tab closes
  const page = await context.newPage();
  const capture = new NetworkCapture(page);

  try {
    while (queue.length > 0) {
      const current = queue.shift();
      if (!current) continue;

      const { url: currentUrl, depth } = current;

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

      const navLog = `[BROWSER CRAWLER] Depth ${depth} - Navigating to: ${currentUrl}`;
      console.log(navLog);
      await sendScanEvent(scanId, 'log.info', { message: navLog });

      try {
        // Navigate in-place
        capture.clear();
        await page.goto(currentUrl, { waitUntil: 'load', timeout: 15000 });
        await streamPageScreenshot(page, scanId);
        
        // Let any SPA javascript run
        await page.waitForTimeout(2000);
        await streamPageScreenshot(page, scanId);

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
            
            // Queue form action if it matches scope and path-prefix
            try {
              const u = new URL(form.action);
              if (isInCrawlScope(form.action, targetUrl, targetHost) && !visited.has(u.toString()) && depth < maxDepth) {
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
            if (isInCrawlScope(req.url, targetUrl, targetHost)) {
              addEndpoint(req.method, req.url, `browser_${req.resourceType}`);
            }
          } catch {}
        }

        // Process found anchor links
        for (const link of links) {
          try {
            const u = new URL(link);
            // Only follow links within the scope (same host + path prefix)
            if (isInCrawlScope(link, targetUrl, targetHost)) {
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
        const errLog = `[BROWSER CRAWLER] [ERROR] Failed to crawl page ${currentUrl}: ${err}`;
        console.error(errLog);
        await sendScanEvent(scanId, 'log.error', { message: errLog });
      }
    }
  } finally {
    await page.close();
    await context.close();
    await browser.close();
  }

  return {
    endpoints: Array.from(discoveredEndpoints.values()),
    screenshots
  };
}
