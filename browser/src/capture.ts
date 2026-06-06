import { Page, Response } from 'playwright';

export interface DiscoveredRequest {
  method: string;
  url: string;
  resourceType: string;
  statusCode?: number;
}

export class NetworkCapture {
  private requests: DiscoveredRequest[] = [];
  private page: Page;
  private responseListener: (response: Response) => void;

  constructor(page: Page) {
    this.page = page;
    this.responseListener = (response: Response) => {
      try {
        const req = response.request();
        this.requests.push({
          method: req.method(),
          url: req.url(),
          resourceType: req.resourceType(),
          statusCode: response.status()
        });
      } catch (e) {
        // Ignore errors if context/page closed
      }
    };
    page.on('response', this.responseListener);
  }

  public getCapturedRequests(): DiscoveredRequest[] {
    return this.requests;
  }

  public clear(): void {
    this.requests = [];
  }

  public dispose(): void {
    try {
      this.page.off('response', this.responseListener);
    } catch (e) {
      // Ignore errors if context/page closed
    }
  }
}
