import { chromium, Browser, BrowserContext, Page } from 'playwright';

export interface Session {
  context: BrowserContext;
  page: Page; // The main/default page (e.g. for Crawling / Auth)
  pages: Map<string, Page>; // Worker-isolated pages by workerId (e.g. sqli, xss, csrf)
  lastAccess: number;
}

export class SessionManager {
  private static instance: SessionManager;
  private sessions: Map<string, Session> = new Map();
  private sessionPromises: Map<string, Promise<Session>> = new Map();
  private sharedBrowser: Browser | null = null;
  private readonly SESSION_TTL = 10 * 60 * 1000; // 10 minutes

  private constructor() {
    setInterval(() => this.cleanup(), 60 * 1000); // Cleanup every minute
  }

  public static getInstance(): SessionManager {
    if (!SessionManager.instance) {
      SessionManager.instance = new SessionManager();
    }
    return SessionManager.instance;
  }

  private async getBrowser(): Promise<Browser> {
    if (this.sharedBrowser && this.sharedBrowser.isConnected()) {
      return this.sharedBrowser;
    }
    console.log('[SESSIONS] Launching shared browser instance...');
    this.sharedBrowser = await chromium.launch({
      headless: true,
      args: [
        '--ignore-certificate-errors',
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });
    return this.sharedBrowser;
  }

  public async getOrCreateSession(scanId: string, proxyPort?: number): Promise<Session> {
    // Check if session creation is already in progress
    const existingPromise = this.sessionPromises.get(scanId);
    if (existingPromise) {
      return existingPromise;
    }

    const existing = this.sessions.get(scanId);
    if (existing) {
      try {
        if (!existing.page.isClosed()) {
          existing.lastAccess = Date.now();
          return existing;
        }
      } catch (e) {
        console.warn(`[SESSIONS] Session ${scanId} check failed, recreating...`);
      }
    }

    const creationPromise = (async () => {
      try {
        console.log(`[SESSIONS] Creating isolated browser context for scan ${scanId} (Proxy: ${proxyPort})`);
        const browser = await this.getBrowser();

        const context = await browser.newContext({
          ignoreHTTPSErrors: true,
          userAgent: 'LastResort-BrowserCrawler/0.1.0',
          proxy: proxyPort ? { server: `http://127.0.0.1:${proxyPort}` } : undefined
        });

        // Inject Scan ID header for proxy identification
        await context.setExtraHTTPHeaders({
          'X-LastResort-Scan-ID': scanId
        });

        const page = await context.newPage();
        this.setupPageListeners(page);

        const session: Session = {
          context,
          page,
          pages: new Map(),
          lastAccess: Date.now()
        };

        this.sessions.set(scanId, session);
        return session;
      } finally {
        this.sessionPromises.delete(scanId);
      }
    })();

    this.sessionPromises.set(scanId, creationPromise);
    return creationPromise;
  }

  public async getPageForWorker(scanId: string, workerId?: string, proxyPort?: number): Promise<Page> {
    const session = await this.getOrCreateSession(scanId, proxyPort);
    session.lastAccess = Date.now();

    if (!workerId) {
      return session.page;
    }

    let workerPage = session.pages.get(workerId);
    if (!workerPage || workerPage.isClosed()) {
      console.log(`[SESSIONS] Creating worker page tab for scan ${scanId}, worker: ${workerId}`);
      workerPage = await session.context.newPage();
      this.setupPageListeners(workerPage);
      session.pages.set(workerId, workerPage);
    }
    return workerPage;
  }

  private setupPageListeners(page: Page) {
    // Attach dialog handler to capture XSS alert/confirm/prompt executions and append a DOM marker (Step 5)
    page.on('dialog', async (dialog) => {
      console.log(`[BROWSER DIALOG DETECTED] type: ${dialog.type()} message: ${dialog.message()}`);
      try {
        await page.evaluate((msg) => {
          const marker = document.createElement('div');
          marker.id = 'lastresort-xss-alert-detected';
          marker.setAttribute('data-dialog-message', msg || '');
          marker.textContent = 'XSS_ALERT_TRIGGERED';
          document.body.appendChild(marker);
        }, dialog.message());
      } catch (e) {
        console.warn(`[BROWSER DIALOG] failed to inject DOM marker:`, e);
      }
      await dialog.dismiss().catch(() => {});
    });

    // Console error capture (Step 5)
    page.on('pageerror', (err) => {
      console.log(`[BROWSER CONSOLE ERROR] ${err.message}`);
    });
  }

  private async cleanup() {
    const now = Date.now();
    for (const [scanId, session] of this.sessions.entries()) {
      if (now - session.lastAccess > this.SESSION_TTL) {
        console.log(`[SESSIONS] Cleaning up idle session for scan ${scanId}`);
        await this.closeSession(scanId);
      }
    }
  }

  public async closeSession(scanId: string) {
    const session = this.sessions.get(scanId);
    if (session) {
      try {
        for (const workerPage of session.pages.values()) {
          try {
            await workerPage.close();
          } catch (e) {}
        }
        await session.page.close();
        await session.context.close();
      } catch (e) {
        console.error(`[SESSIONS] Error closing context for ${scanId}:`, e);
      } finally {
        this.sessions.delete(scanId);
      }
    }
  }

  public async shutdown() {
    console.log('[SESSIONS] Shutting down shared browser and closing all contexts...');
    for (const scanId of this.sessions.keys()) {
      await this.closeSession(scanId);
    }
    if (this.sharedBrowser) {
      await this.sharedBrowser.close().catch(() => {});
      this.sharedBrowser = null;
    }
  }
}
