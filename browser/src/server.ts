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

app.post('/action', async (req: Request, res: Response) => {
  let { scanId, url, action, selector, value, proxyPort } = req.body;

  if (!scanId) {
    return res.status(400).json({ error: 'scanId is required.' });
  }

  if (selector) {
    selector = cleanSelector(selector);
  }

  console.log(`[SERVER] Received action: ${action} on ${url || 'current page'} (scan: ${scanId}) with selector: ${selector}`);

  let preScreenshotBase64 = '';
  let preDom = '';
  const prefix = `${Date.now()}_${action}_${selector ? selector.replace(/[^a-z0-9]/gi, '_') : 'none'}`.slice(0, 100);
  const screenshotsDir = path.join(__dirname, '..', '..', 'data', 'screenshots', scanId);
  const domsDir = path.join(__dirname, '..', '..', 'data', 'doms', scanId);

  try {
    const session = await sessionManager.getOrCreateSession(scanId, proxyPort ? Number(proxyPort) : undefined);
    const page = session.page;

    if (!fs.existsSync(screenshotsDir)) {
      fs.mkdirSync(screenshotsDir, { recursive: true });
    }
    if (!fs.existsSync(domsDir)) {
      fs.mkdirSync(domsDir, { recursive: true });
    }

    if (url) {
      await page.goto(url, { waitUntil: 'networkidle' });
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
