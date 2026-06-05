import express, { Request, Response } from 'express';
import cors from 'cors';
import * as path from 'path';
import * as fs from 'fs';
import { runBrowserCrawl } from './crawler';
import { SessionManager } from './sessions';
import { scrapePageContext } from './dom';

const app = express();
const port = process.env.PORT || 3010;

app.use(cors());
app.use(express.json());

const sessionManager = SessionManager.getInstance();

app.get('/health', (req: Request, res: Response) => {
  res.json({ status: 'ok', service: 'lastresort-browser-crawler' });
});

app.post('/crawl', async (req: Request, res: Response) => {
  const { scanId, targetUrl, proxyPort } = req.body;

  if (!scanId || !targetUrl) {
    return res.status(400).json({ error: 'scanId and targetUrl are required parameters.' });
  }

  try {
    console.log(`[SERVER] Received crawl request for scan ${scanId} targeting ${targetUrl}`);
    
    // Get session to ensure shared context
    const session = await sessionManager.getOrCreateSession(scanId, proxyPort ? Number(proxyPort) : undefined);
    
    const results = await runBrowserCrawl(scanId, targetUrl, proxyPort ? Number(proxyPort) : undefined, 2, session);
    
    return res.json({
      success: true,
      endpoints: results.endpoints,
      screenshots: results.screenshots,
      forms: results.forms
    });
  } catch (error: any) {
    console.error(`[SERVER] [ERROR] Browser crawl failed:`, error);
    return res.status(500).json({
      success: false,
      error: error.message || 'An unexpected error occurred during browser crawl.'
    });
  }
});

function cleanSelector(selector: string): string {
  if (!selector) return selector;
  // Replace :contains("...") or :contains('...') or :contains(...) with :has-text(...)
  return selector.replace(/:contains\((["']?)(.*?)\1\)/g, ':has-text("$2")');
}

async function sendScanEvent(scanId: string, eventType: string, data: any) {
  try {
    await fetch('http://127.0.0.1:8443/api/v1/scan/event', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scan_id: scanId, event_type: eventType, data })
    });
  } catch (err) {
    console.error(`[BROWSER SERVER] Failed to push event ${eventType}:`, err);
  }
}

async function streamPageScreenshot(page: any, scanId: string) {
  try {
    const buffer = await page.screenshot({ type: 'png' });
    const base64 = buffer.toString('base64');
    await sendScanEvent(scanId, 'browser.screenshot', { image: `data:image/png;base64,${base64}` });
  } catch (err) {}
}

async function injectOverlayAndStream(page: any, scanId: string, action: string, selector: string, value: string) {
  try {
    if (!selector) return;
    
    await page.evaluate(({ action, selector, value }: { action: string, selector: string, value: string }) => {
      let style = document.getElementById('lastresort-overlay-style');
      if (!style) {
        style = document.createElement('style');
        style.id = 'lastresort-overlay-style';
        style.innerHTML = `
          @keyframes lr-ripple {
            0% { transform: scale(0); opacity: 0.8; }
            100% { transform: scale(3); opacity: 0; }
          }
          @keyframes lr-pulse {
            0%, 100% { box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.4); }
            50% { box-shadow: 0 0 0 6px rgba(245, 158, 11, 0.8); }
          }
          .lr-cursor {
            position: absolute;
            width: 24px;
            height: 24px;
            background: rgba(245, 158, 11, 0.9);
            border: 2px solid #ffffff;
            border-radius: 50%;
            pointer-events: none;
            z-index: 10000000;
            box-shadow: 0 0 10px rgba(0,0,0,0.5);
            transition: all 0.3s ease-in-out;
          }
          .lr-ripple {
            position: absolute;
            width: 30px;
            height: 30px;
            background: rgba(245, 158, 11, 0.6);
            border-radius: 50%;
            pointer-events: none;
            z-index: 10000000;
            animation: lr-ripple 0.5s ease-out forwards;
          }
          .lr-highlight {
            outline: 3px dashed #f59e0b !important;
            animation: lr-pulse 1.5s infinite;
          }
          .lr-keystroke-banner {
            position: fixed;
            bottom: 30px;
            left: 50%;
            transform: translateX(-50%);
            background: rgba(9, 9, 11, 0.95);
            border: 1px solid #f59e0b;
            color: #f59e0b;
            padding: 10px 20px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 13px;
            z-index: 10000001;
            pointer-events: none;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
          }
        `;
        document.head.appendChild(style);
      }

      const el = document.querySelector(selector) as HTMLElement;
      if (!el) return;

      el.classList.add('lr-highlight');

      const rect = el.getBoundingClientRect();
      const x = rect.left + window.scrollX + rect.width / 2;
      const y = rect.top + window.scrollY + rect.height / 2;

      if (action === 'click') {
        const cursor = document.createElement('div');
        cursor.id = 'lr-active-cursor';
        cursor.className = 'lr-cursor';
        cursor.style.left = (x - 12) + 'px';
        cursor.style.top = (y - 12) + 'px';
        document.body.appendChild(cursor);

        const ripple = document.createElement('div');
        ripple.id = 'lr-active-ripple';
        ripple.className = 'lr-ripple';
        ripple.style.left = (x - 15) + 'px';
        ripple.style.top = (y - 15) + 'px';
        document.body.appendChild(ripple);
      } else if (action === 'fill' || action === 'type') {
        const banner = document.createElement('div');
        banner.id = 'lr-active-banner';
        banner.className = 'lr-keystroke-banner';
        banner.innerText = `[TYPING] "${value}"`;
        document.body.appendChild(banner);
      }
    }, { action, selector, value });

    await streamPageScreenshot(page, scanId);
    await page.waitForTimeout(500);

    await page.evaluate(() => {
      const cursor = document.getElementById('lr-active-cursor');
      if (cursor) cursor.remove();
      const ripple = document.getElementById('lr-active-ripple');
      if (ripple) ripple.remove();
      const banner = document.getElementById('lr-active-banner');
      if (banner) banner.remove();
      
      const highlighted = document.querySelectorAll('.lr-highlight');
      highlighted.forEach(el => el.classList.remove('lr-highlight'));
    });
  } catch (err) {
    console.error('[BROWSER] Failed to render action overlay:', err);
  }
}

app.post('/action', async (req: Request, res: Response) => {
  let { scanId, workerId, url, action, selector, value, proxyPort } = req.body;

  if (!scanId) {
    return res.status(400).json({ error: 'scanId is required.' });
  }

  if (selector) {
    selector = cleanSelector(selector);
  }

  console.log(`[SERVER] Received action: ${action} on ${url || 'current page'} (scan: ${scanId}, worker: ${workerId || 'default'}) with selector: ${selector}`);

  let preScreenshotBase64 = '';
  let preDom = '';
  const prefix = `${Date.now()}_${action}_${selector ? selector.replace(/[^a-z0-9]/gi, '_') : 'none'}`.slice(0, 100);
  const screenshotsDir = path.join(__dirname, '..', '..', 'data', 'screenshots', scanId);
  const domsDir = path.join(__dirname, '..', '..', 'data', 'doms', scanId);

  try {
    const page = await sessionManager.getPageForWorker(scanId, workerId, proxyPort ? Number(proxyPort) : undefined);

    if (!fs.existsSync(screenshotsDir)) {
      fs.mkdirSync(screenshotsDir, { recursive: true });
    }
    if (!fs.existsSync(domsDir)) {
      fs.mkdirSync(domsDir, { recursive: true });
    }

    if (url) {
      await page.goto(url, { waitUntil: 'load' });
      await streamPageScreenshot(page, scanId);
    }

    // Capture pre-action
    try {
      const buffer = await page.screenshot({ fullPage: true });
      fs.writeFileSync(path.join(screenshotsDir, `${prefix}_pre.png`), buffer);
      preScreenshotBase64 = buffer.toString('base64');
      preDom = await page.content();
      fs.writeFileSync(path.join(domsDir, `${prefix}_pre.html`), preDom);
    } catch (err) {
      console.error('[SERVER] Failed to capture pre-action state', err);
    }

    // Perform action
    try {
      await injectOverlayAndStream(page, scanId, action, selector, value);

      if (action === 'click') {
        await page.click(selector);
      } else if (action === 'fill') {
        await page.fill(selector, value);
      } else if (action === 'type') {
        await page.type(selector, value);
      } else if (action === 'evaluate') {
        await page.evaluate(value);
      } else if (action === 'navigate' && url) {
        // already handled by goto above
      }

      await page.waitForTimeout(1000);
    } catch (actionErr: any) {
      // Capture post-action even on action failure
      let postScreenshotBase64 = '';
      let postDom = '';
      try {
        const buffer = await page.screenshot({ fullPage: true });
        fs.writeFileSync(path.join(screenshotsDir, `${prefix}_post.png`), buffer);
        postScreenshotBase64 = buffer.toString('base64');
        postDom = await page.content();
        fs.writeFileSync(path.join(domsDir, `${prefix}_post.html`), postDom);
        await sendScanEvent(scanId, 'browser.screenshot', { image: `data:image/png;base64,${postScreenshotBase64}` });
      } catch (err) {}

      // Return 200 success: false on failure
      return res.status(200).json({
        success: false,
        failureReason: actionErr.message || 'Action execution failed',
        screenshotBase64: postScreenshotBase64 || preScreenshotBase64,
        pageSource: postDom || preDom,
        currentUrl: page.url(),
        pageTitle: await page.title().catch(() => ''),
        preActionScreenshot: preScreenshotBase64,
        preActionDOM: preDom,
        postActionScreenshot: postScreenshotBase64,
        postActionDOM: postDom
      });
    }

    // Capture post-action on success
    const postScreenshot = await page.screenshot({ type: 'png' });
    await streamPageScreenshot(page, scanId);
    const postDom = await page.content();
    fs.writeFileSync(path.join(screenshotsDir, `${prefix}_post.png`), postScreenshot);
    fs.writeFileSync(path.join(domsDir, `${prefix}_post.html`), postDom);

    const context = await scrapePageContext(page);
    const cookies = await page.context().cookies();

    return res.json({
      success: true,
      failureReason: '',
      screenshotBase64: postScreenshot.toString('base64'),
      pageSource: postDom,
      currentUrl: page.url(),
      pageTitle: await page.title(),
      links: context.links,
      buttons: context.buttons,
      forms: context.forms,
      cookies,
      localStorage: context.localStorage,
      preActionScreenshot: preScreenshotBase64,
      preActionDOM: preDom,
      postActionScreenshot: postScreenshot.toString('base64'),
      postActionDOM: postDom
    });

  } catch (error: any) {
    console.error(`[SERVER] [ACTION ERROR]`, error);
    // Even if top-level setup failed, return 200 with success: false
    return res.status(200).json({ 
      success: false, 
      failureReason: error.message || 'Unknown browser error',
      screenshotBase64: '',
      pageSource: '',
      currentUrl: '',
      pageTitle: ''
    });
  }
});

app.post('/end-session', async (req: Request, res: Response) => {
  const { scanId } = req.body;
  if (scanId) {
    await sessionManager.closeSession(scanId);
    return res.json({ success: true, message: `Session ${scanId} closed.` });
  }
  return res.status(400).json({ error: 'scanId is required.' });
});

app.listen(Number(port), '127.0.0.1', () => {
  console.log(`[SERVER] Browser crawler service listening at http://127.0.0.1:${port}`);
});
