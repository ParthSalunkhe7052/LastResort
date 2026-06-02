import { Page, Request } from 'playwright';

export interface DiscoveredRequest {
  method: string;
  url: string;
  resourceType: string;
}

export class NetworkCapture {
  private requests: DiscoveredRequest[] = [];

  constructor(page: Page) {
    page.on('request', (request: Request) => {
      this.requests.push({
        method: request.method(),
        url: request.url(),
        resourceType: request.resourceType(),
      });
    });
  }

  public getCapturedRequests(): DiscoveredRequest[] {
    return this.requests;
  }
}
