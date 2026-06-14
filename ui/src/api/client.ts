import { createPromiseClient } from '@connectrpc/connect'
import { createConnectTransport } from '@connectrpc/connect-web'
import { ScanService } from '../gen/scan/v1/scan_connect'

export const BASE_URL = 'http://127.0.0.1:8443'

const transport = createConnectTransport({
  baseUrl: BASE_URL,
})

export const client = createPromiseClient(ScanService, transport)
