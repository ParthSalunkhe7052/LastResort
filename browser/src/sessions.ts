import { chromium, Browser, BrowserContext, Page } from 'playwright';

export interface Session {
  browser: Browser;
  context: BrowserContext;
  page: Page;
  lastAccess: number;
}

export class SessionManager {
  private static instance: SessionManager;
  private sessions: Map<string, Session> = new Map();
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

  public async getOrCreateSession(scanId: string, proxyPort?: number): Promise<Session> {
    const existing = this.sessions.get(scanId);
    if (existing) {
      try {
        // Check if page/context is still alive
        if (!existing.page.isClosed() && existing.browser.isConnected()) {
          existing.lastAccess = Date.now();
          return existing;
        }
      } catch (e) {
        console.warn(`[SESSIONS] Session ${scanId} check failed, recreating...`);
      }
    }

    console.log(`[SESSIONS] Creating new session for scan ${scanId} (Proxy: ${proxyPort})`);
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
      ignoreHTTPSErrors: true,
      userAgent: 'LastResort-BrowserCrawler/0.1.0'
    });

    const page = await context.newPage();
    const session: Session = {
      browser,
      context,
      page,
      lastAccess: Date.now()
    };

    this.sessions.set(scanId, session);
    return session;
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
        await session.page.close();
        await session.context.close();
        await session.browser.close();
      } catch (e) {
        console.error(`[SESSIONS] Error closing session ${scanId}:`, e);
      } finally {
        this.sessions.delete(scanId);
      }
    }
  }
}
