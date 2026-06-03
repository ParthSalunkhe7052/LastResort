import { createPromiseClient } from '@connectrpc/connect'
import { createConnectTransport } from '@connectrpc/connect-web'
import { ScanService } from '../gen/scan/v1/scan_connect'

const transport = createConnectTransport({
  baseUrl: 'http://127.0.0.1:8443',
})

export const client = createPromiseClient(ScanService, transport)
