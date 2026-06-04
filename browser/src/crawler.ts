import { Page } from 'playwright';
import { NetworkCapture } from './capture';
import { takeScreenshot } from './screenshot';
import { Session, SessionManager } from './sessions';
import { scrapePageContext } from './dom';
import * as url from 'url';

export interface CrawlResult {
  endpoints: Array<{ method: string; url: string; source: string }>;
  screenshots: Array<{ url: string; path: string }>;
  forms: Array<any>;
}

const sessionManager = SessionManager.getInstance();

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

async function streamPageScreenshot(page: Page, scanId: string) {
  try {
    const buffer = await page.screenshot({ type: 'png' });
    const base64 = buffer.toString('base64');
    await sendScanEvent(scanId, 'browser.screenshot', { image: `data:image/png;base64,${base64}` });
  } catch (err) {}
}

function isInCrawlScope(urlStr: string, seedUrl: string, targetHost: string): boolean {
  try {
    const u = new URL(urlStr);
    const s = new URL(seedUrl);
    if (u.host !== targetHost) return false;
    let sCtx = s.pathname;
    
    // Extract directory context by removing everything after the last slash
    const lastSlash = sCtx.lastIndexOf('/');
    if (lastSlash !== -1) {
      sCtx = sCtx.slice(0, lastSlash + 1);
    }
    
    if (sCtx && sCtx !== '/') {
      let uPath = u.pathname;
      if (!uPath.endsWith('/')) uPath += '/';
      return uPath.startsWith(sCtx);
    }
    return true;
  } catch {
    return false;
  }
}

function shouldCrawlUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr);
    const pathname = u.pathname.toLowerCase();
    const blacklistedExtensions = [
      '.pdf', '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx', 
      '.zip', '.tar', '.gz', '.tgz', '.rar', '.7z',
      '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
      '.mp4', '.mp3', '.webm', '.ogg', '.wav', '.avi', '.mov',
      '.css', '.js', '.map', '.woff', '.woff2', '.ttf', '.eot'
    ];
    return !blacklistedExtensions.some(ext => pathname.endsWith(ext));
  } catch {
    return false;
  }
}

export async function runBrowserCrawl(
  scanId: string,
  targetUrl: string,
  proxyPort?: number,
  maxDepth: number = 2,
  providedSession?: Session
): Promise<CrawlResult> {
  const parsedTarget = url.parse(targetUrl);
  const targetHost = parsedTarget.host;
  if (!targetHost) throw new Error(`Invalid target URL: ${targetUrl}`);

  const logMessage = `[BROWSER CRAWLER] Starting crawl for ${targetUrl}`;
  console.log(logMessage);
  await sendScanEvent(scanId, 'log.info', { message: logMessage });

  const session = providedSession || await sessionManager.getOrCreateSession(scanId, proxyPort);
  const page = session.page;

  const visited = new Set<string>();
  const queue: Array<{ url: string; depth: number }> = [{ url: targetUrl, depth: 1 }];
  const discoveredEndpoints: Map<string, { method: string; url: string; source: string }> = new Map();
  const screenshots: Array<{ url: string; path: string }> = [];
  const discoveredForms: Map<string, any> = new Map();

  const addEndpoint = (method: string, urlStr: string, source: string) => {
    try {
      const u = new URL(urlStr);
      u.hash = '';
      const normalized = u.toString();
      const key = `${method.toUpperCase()}:${normalized}`;
      if (!discoveredEndpoints.has(key)) {
        discoveredEndpoints.set(key, { method: method.toUpperCase(), url: normalized, source });
      }
    } catch {}
  };

  const capture = new NetworkCapture(page);

  try {
    while (queue.length > 0) {
      if (visited.size >= 10) {
        const limitLog = `[BROWSER CRAWLER] Visited page limit (10) reached. Stopping crawl.`;
        console.log(limitLog);
        await sendScanEvent(scanId, 'log.info', { message: limitLog });
        break;
      }

      const current = queue.shift();
      if (!current) continue;

      const { url: currentUrl, depth } = current;
      let normalizedCurrentUrl = currentUrl;
      try {
        const u = new URL(currentUrl);
        u.hash = '';
        normalizedCurrentUrl = u.toString();
      } catch {}

      if (visited.has(normalizedCurrentUrl) || depth > maxDepth + 1) continue;
      visited.add(normalizedCurrentUrl);

      const navLog = `[BROWSER CRAWLER] Depth ${depth} - Navigating: ${currentUrl}`;
      console.log(navLog);
      await sendScanEvent(scanId, 'log.info', { message: navLog });

      try {
        capture.clear();
        await page.goto(currentUrl, { waitUntil: 'load', timeout: 15000 });
        await streamPageScreenshot(page, scanId);
        await page.waitForTimeout(2000);
        await streamPageScreenshot(page, scanId);

        const screenshotPath = await takeScreenshot(page, scanId, currentUrl);
        if (screenshotPath) screenshots.push({ url: currentUrl, path: screenshotPath });

        addEndpoint('GET', currentUrl, 'browser_crawl');

        const context = await scrapePageContext(page);

        // Process discovered links
        for (const link of context.links) {
          if (isInCrawlScope(link.href!, targetUrl, targetHost)) {
            addEndpoint('GET', link.href!, 'browser_link');
            if (!visited.has(link.href!) && depth <= maxDepth && shouldCrawlUrl(link.href!)) {
              queue.push({ url: link.href!, depth: depth + 1 });
            }
          }
        }

        // Process discovered forms
        for (const form of context.forms) {
          addEndpoint(form.method, form.action, 'browser_form');
          if (isInCrawlScope(form.action, targetUrl, targetHost)) {
            const formKey = `${form.method.toUpperCase()}:${form.action}:${form.selector}`;
            if (!discoveredForms.has(formKey)) {
              discoveredForms.set(formKey, {
                url: currentUrl,
                selector: form.selector,
                action: form.action,
                method: form.method,
                inputs: form.inputs
              });
            }
            if (!visited.has(form.action) && depth <= maxDepth && shouldCrawlUrl(form.action)) {
              queue.push({ url: form.action, depth: depth + 1 });
            }
          }
        }

        // Process network requests
        const captured = capture.getCapturedRequests();
        for (const req of captured) {
          if (isInCrawlScope(req.url, targetUrl, targetHost)) {
            addEndpoint(req.method, req.url, `browser_${req.resourceType}`);
          }
        }
      } catch (err) {
        const errLog = `[BROWSER CRAWLER] [ERROR] Failed ${currentUrl}: ${err}`;
        console.error(errLog);
        await sendScanEvent(scanId, 'log.error', { message: errLog });
      }
    }
  } finally {
    if (!providedSession) {
      await sessionManager.closeSession(scanId);
    }
  }

  return {
    endpoints: Array.from(discoveredEndpoints.values()),
    screenshots,
    forms: Array.from(discoveredForms.values())
  };
}
