import { useState, useEffect } from 'react'
import { Network, RefreshCw } from 'lucide-react'
import { client } from '../../api/client'

interface EndpointRecord {
  id: string
  scanId: string
  method: string
  url: string
  source: string
  statusCode: number
  contentType: string
}

interface EndpointMapProps {
  activeScanId: string | null
}

export default function EndpointMap({ activeScanId }: EndpointMapProps) {
  const [endpoints, setEndpoints] = useState<EndpointRecord[]>([])
  const [isLoading, setIsLoading] = useState(false)

  const fetchEndpoints = async () => {
    setIsLoading(true)
    try {
      const res = await client.listEndpoints({ scanId: activeScanId || '' })
      const records = res.endpoints.map(ep => ({
        id: ep.id,
        scanId: ep.scanId,
        method: ep.method,
        url: ep.url,
        source: ep.source,
        statusCode: ep.statusCode,
        contentType: ep.contentType
      }))
      setEndpoints(records)
    } catch (err) {
      console.error('Failed to fetch endpoints:', err)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchEndpoints()
  }, [activeScanId])

  return (
    <div className="flex-1 border border-zinc-800 bg-zinc-900/10 rounded-xl flex flex-col overflow-hidden">
      <div className="px-6 py-4 border-b border-zinc-800 flex items-center justify-between shrink-0 bg-zinc-900/40">
        <h3 className="font-semibold text-sm flex items-center space-x-2 text-zinc-100">
          <Network className="w-4 h-4 text-orange-400" />
          <span>Discovered Endpoint Map</span>
        </h3>
        <button 
          onClick={fetchEndpoints}
          disabled={isLoading}
          className="flex items-center space-x-1 px-2.5 py-1 bg-zinc-800 hover:bg-zinc-700 transition rounded text-[10px] font-mono text-zinc-300 cursor-pointer"
        >
          <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {endpoints.length === 0 ? (
          <div className="p-12 text-center italic text-zinc-600 text-xs">No endpoints crawled yet. Run a scan to discover endpoints.</div>
        ) : (
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="border-b border-zinc-800 bg-zinc-900/30 text-zinc-400 sticky top-0">
                <th className="p-3 w-20">Method</th>
                <th className="p-3">URL</th>
                <th className="p-3 w-32">Source</th>
                <th className="p-3 w-20">Status</th>
                <th className="p-3 w-36">Content Type</th>
              </tr>
            </thead>
            <tbody>
              {endpoints.map(ep => (
                <tr key={ep.id} className="border-b border-zinc-800/60 hover:bg-zinc-800/20 transition">
                  <td className="p-3 font-bold text-zinc-300">{ep.method}</td>
                  <td className="p-3 text-zinc-300 break-all">{ep.url}</td>
                  <td className="p-3">
                    <span className="bg-zinc-850 px-2 py-0.5 rounded border border-zinc-800 text-[10px] text-zinc-400 capitalize">{ep.source}</span>
                  </td>
                  <td className="p-3">
                    {ep.statusCode > 0 ? (
                      <span className={`px-1.5 py-0.5 rounded border text-[10px] ${
                        ep.statusCode >= 200 && ep.statusCode < 300 ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                        ep.statusCode >= 300 && ep.statusCode < 400 ? 'bg-sky-500/10 border-sky-500/20 text-sky-400' :
                        'bg-rose-500/10 border-rose-500/20 text-rose-400'
                      }`}>{ep.statusCode}</span>
                    ) : (
                      <span className="text-zinc-600">-</span>
                    )}
                  </td>
                  <td className="p-3 text-zinc-500 truncate max-w-[150px]">{ep.contentType || 'unknown'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
