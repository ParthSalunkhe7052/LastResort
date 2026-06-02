import { Page } from 'playwright';
import * as path from 'path';
import * as fs from 'fs';

export async function takeScreenshot(page: Page, scanId: string, url: string): Promise<string | null> {
  try {
    const safeUrl = url.replace(/[^a-z0-9]/gi, '_').toLowerCase().slice(0, 100);
    const filename = `${Date.now()}_${safeUrl}.png`;
    const dir = path.join(__dirname, '..', '..', 'data', 'screenshots', scanId);
    
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    const screenshotPath = path.join(dir, filename);
    await page.screenshot({ path: screenshotPath, fullPage: true });
    return screenshotPath;
  } catch (error) {
    console.error(`[SCREENSHOT] [ERROR] Failed to take screenshot of ${url}:`, error);
    return null;
  }
}
