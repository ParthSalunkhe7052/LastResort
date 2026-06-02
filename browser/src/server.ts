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

app.listen(port, () => {
  console.log(`[SERVER] Browser crawler service listening at http://localhost:${port}`);
});
