import express, { Request, Response } from 'express';
import cors from 'cors';
import { runBrowserCrawl } from './crawler';

const app = express();
const port = process.env.PORT || 3010;

app.use(cors());
app.use(express.json());

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
    const results = await runBrowserCrawl(scanId, targetUrl, proxyPort ? Number(proxyPort) : undefined);
    
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

import { chromium } from 'playwright';

function cleanSelector(selector: string): string {
  if (!selector) return selector;
  // Replace :contains("...") or :contains('...') or :contains(...) with :has-text(...)
  return selector.replace(/:contains\((["']?)(.*?)\1\)/g, ':has-text("$2")');
}

app.post('/action', async (req: Request, res: Response) => {
  let { scanId, url, action, selector, value, proxyPort } = req.body;

  if (selector) {
    selector = cleanSelector(selector);
  }

  console.log(`[SERVER] Received action: ${action} on ${url} (scan: ${scanId}) with selector: ${selector}`);

  const browser = await chromium.launch({
    headless: true,
    args: [
      '--ignore-certificate-errors',
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ],
    proxy: proxyPort ? { server: `http://127.0.0.1:${proxyPort}` } : undefined
  });

  try {
    const context = await browser.newContext({
      ignoreHTTPSErrors: true
    });
    const page = await context.newPage();

    if (url) {
      await page.goto(url, { waitUntil: 'networkidle' });
    }

    if (action === 'click') {
      await page.click(selector);
    } else if (action === 'fill') {
      await page.fill(selector, value);
    } else if (action === 'type') {
      await page.type(selector, value);
    }

    // Wait for any effects
    await page.waitForTimeout(1000);

    const screenshot = await page.screenshot({ type: 'png' });
    const pageSource = await page.content();

    return res.json({
      success: true,
      screenshot: screenshot.toString('base64'),
      pageSource
    });
  } catch (error: any) {
    console.error(`[SERVER] [ACTION ERROR]`, error);
    return res.status(500).json({ success: false, error: error.message });
  } finally {
    await browser.close();
  }
});

app.listen(Number(port), '127.0.0.1', () => {
  console.log(`[SERVER] Browser crawler service listening at http://127.0.0.1:${port}`);
});
