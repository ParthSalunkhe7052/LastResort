// Proxy history viewer module

export interface ProxyFlowRecord {
  id: string
  scanId: string
  method: string
  url: string
  requestHeaders: string
  requestBody: string
  responseHeaders: string
  responseBody: string
  responseStatus: number
  createdAt: string
}

interface ProxyHistoryProps {
  flows: ProxyFlowRecord[]
  selectedFlow: ProxyFlowRecord | null
  setSelectedFlow: (flow: ProxyFlowRecord | null) => void
  flowSearch: string
  setFlowSearch: (search: string) => void
  onSendToRepeater: (host: string, useTls: boolean, request: string) => void
}

export default function ProxyHistory({
  flows,
  selectedFlow,
  setSelectedFlow,
  flowSearch,
  setFlowSearch,
  onSendToRepeater
}: ProxyHistoryProps) {
  const formatHeadersBody = (headersStr: string, bodyStr: string) => {
    try {
      const parsedHeaders = JSON.parse(headersStr)
      let headerText = ''
      for (const [k, v] of Object.entries(parsedHeaders)) {
        headerText += `${k}: ${(v as string[]).join(', ')}\n`
      }
      return `${headerText}\n${bodyStr}`
    } catch {
      return `${headersStr}\n\n${bodyStr}`
    }
  }

  const filteredFlows = flows.filter(f => 
    f.url.toLowerCase().includes(flowSearch.toLowerCase()) || 
    f.method.toLowerCase().includes(flowSearch.toLowerCase())
  )

  return (
    <div className="flex-1 flex gap-6 overflow-hidden">
      {/* Flows List */}
      <div className="flex-1 border border-zinc-800 bg-zinc-900/10 rounded-xl flex flex-col overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between shrink-0">
          <input 
            type="text" 
            placeholder="Search proxy history..." 
            value={flowSearch}
            onChange={e => setFlowSearch(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-300 rounded px-3 py-1.5 focus:outline-none focus:border-sky-500 w-64"
          />
          <span className="text-xs text-zinc-500 font-mono">Flows intercepted: {filteredFlows.length}</span>
        </div>

        <div className="flex-1 overflow-y-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/40 text-zinc-400 sticky top-0">
                <th className="p-3 w-16">ID</th>
                <th className="p-3 w-20">Method</th>
                <th className="p-3">URL</th>
                <th className="p-3 w-24">Status</th>
                <th className="p-3 w-24">Time</th>
              </tr>
            </thead>
            <tbody>
              {filteredFlows.length === 0 ? (
                <tr>
                  <td colSpan={5} className="p-6 text-center italic text-zinc-600">No proxy history recorded. Verify browser is configured to use localhost:8080 proxy port.</td>
                </tr>
              ) : (
                filteredFlows.map(f => (
                  <tr 
                    key={f.id}
                    onClick={() => setSelectedFlow(f)}
                    className={`border-b border-zinc-800/60 hover:bg-zinc-800/30 cursor-pointer transition ${
                      selectedFlow?.id === f.id ? 'bg-sky-500/5' : ''
                    }`}
                  >
                    <td className="p-3 text-zinc-500">#{f.id}</td>
                    <td className="p-3 font-bold text-zinc-300">{f.method}</td>
                    <td className="p-3 text-zinc-300 truncate max-w-[400px]">{f.url}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded border text-[10px] ${
                        f.responseStatus >= 200 && f.responseStatus < 300 ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                        f.responseStatus >= 300 && f.responseStatus < 400 ? 'bg-sky-500/10 border-sky-500/20 text-sky-400' :
                        'bg-rose-500/10 border-rose-500/20 text-rose-400'
                      }`}>{f.responseStatus}</span>
                    </td>
                    <td className="p-3 text-zinc-500">{f.createdAt}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side raw viewer */}
      <div className="w-[500px] border border-zinc-800 bg-zinc-950 rounded-xl flex flex-col overflow-hidden shrink-0">
        {selectedFlow ? (
          <div className="flex-1 flex flex-col overflow-hidden">
            <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between shrink-0 bg-zinc-900/40">
              <h4 className="font-semibold text-xs font-mono text-zinc-200">Captured Flow #{selectedFlow.id}</h4>
              <button 
                onClick={() => {
                  const urlObj = new URL(selectedFlow.url)
                  const rawReq = `${selectedFlow.method} ${urlObj.pathname}${urlObj.search} HTTP/1.1\r\n` +
                                 `Host: ${urlObj.host}\r\n` +
                                 `User-Agent: LastResort/0.1.0\r\n` +
                                 `Accept: */*\r\n` +
                                 `Connection: close\r\n\r\n`
                  onSendToRepeater(urlObj.host, selectedFlow.url.startsWith('https'), rawReq)
                }}
                className="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-[10px] font-mono px-2 py-1 rounded text-zinc-300 hover:text-zinc-100 cursor-pointer"
              >
                Send to Repeater
              </button>
            </div>

            <div className="flex-1 p-6 overflow-y-auto space-y-6">
              {/* Request block */}
              <div>
                <span className="block text-[10px] font-mono text-sky-400 mb-2">RAW PLAINTEXT REQUEST</span>
                <pre className="font-mono text-xs bg-zinc-950 p-4 border border-zinc-800 rounded-lg text-zinc-300 overflow-x-auto whitespace-pre-wrap">
                  {selectedFlow.method} {new URL(selectedFlow.url).pathname} HTTP/1.1{"\n"}
                  {formatHeadersBody(selectedFlow.requestHeaders, selectedFlow.requestBody)}
                </pre>
              </div>

              {/* Response block */}
              <div>
                <span className="block text-[10px] font-mono text-emerald-400 mb-2">DECRYPTED RESPONSE</span>
                <pre className="font-mono text-xs bg-zinc-950 p-4 border border-zinc-800 rounded-lg text-zinc-300 overflow-x-auto whitespace-pre-wrap">
                  HTTP/1.1 {selectedFlow.responseStatus} OK{"\n"}
                  {formatHeadersBody(selectedFlow.responseHeaders, selectedFlow.responseBody)}
                </pre>
              </div>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-zinc-600 text-xs italic">
            Select a flow transaction to view raw details.
          </div>
        )}
      </div>
    </div>
  )
}
