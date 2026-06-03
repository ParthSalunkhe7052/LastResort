import express, { Request, Response } from 'express';
import cors from 'cors';
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
    
    const results = await runBrowserCrawl(scanId, targetUrl, proxyPort ? Number(proxyPort) : undefined, 3, session);
    
    return res.json({
      success: true,
      endpoints: results.endpoints,
      screenshots: results.screenshots
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

  try {
    const session = await sessionManager.getOrCreateSession(scanId, proxyPort ? Number(proxyPort) : undefined);
    const page = session.page;

    if (url) {
      await page.goto(url, { waitUntil: 'networkidle' });
    }

    if (action === 'click') {
      await page.click(selector);
    } else if (action === 'fill') {
      await page.fill(selector, value);
    } else if (action === 'type') {
      await page.type(selector, value);
    } else if (action === 'navigate' && url) {
      // already handled by goto above, but explicitly for clarity
    }

    // Wait for any effects
    await page.waitForTimeout(1000);

    const screenshot = await page.screenshot({ type: 'png' });
    const pageSource = await page.content();
    const context = await scrapePageContext(page);
    const cookies = await page.context().cookies();

    return res.json({
      success: true,
      screenshot: screenshot.toString('base64'),
      pageSource,
      currentUrl: page.url(),
      pageTitle: await page.title(),
      links: context.links,
      buttons: context.buttons,
      forms: context.forms,
      cookies,
      localStorage: context.localStorage
    });
  } catch (error: any) {
    console.error(`[SERVER] [ACTION ERROR]`, error);
    return res.status(500).json({ success: false, error: error.message });
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
