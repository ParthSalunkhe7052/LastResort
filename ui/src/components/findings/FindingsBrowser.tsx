import { AlertTriangle } from 'lucide-react'

export interface FindingRecord {
  id: string
  scanId: string
  title: string
  description: string
  severity: string
  vulnerabilityType: string
  endpoint: string
  payload: string
  responseStatus: number
  confidence: number
  isFalsePositive: boolean
  createdAt: string
}

interface FindingsBrowserProps {
  findings: FindingRecord[]
  selectedFinding: FindingRecord | null
  setSelectedFinding: (finding: FindingRecord | null) => void
}

export default function FindingsBrowser({
  findings,
  selectedFinding,
  setSelectedFinding
}: FindingsBrowserProps) {
  return (
    <div className="flex-1 flex gap-6 overflow-hidden">
      {/* Findings list */}
      <div className="flex-1 border border-zinc-800 bg-zinc-900/10 rounded-xl flex flex-col overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800 bg-zinc-900/40 shrink-0">
          <h3 className="font-semibold text-sm flex items-center space-x-2 text-zinc-100">
            <AlertTriangle className="w-4 h-4 text-rose-500" />
            <span>Discovered Security Vulnerabilities</span>
          </h3>
        </div>

        <div className="flex-1 overflow-y-auto">
          {findings.length === 0 ? (
            <div className="p-12 text-center italic text-zinc-600 text-xs">No vulnerabilities recorded in SQLite database. Start a scan target to run audits.</div>
          ) : (
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="border-b border-zinc-800 bg-zinc-900/30 text-zinc-400 sticky top-0">
                  <th className="p-3">Title</th>
                  <th className="p-3 w-40">Type</th>
                  <th className="p-3 w-28">Severity</th>
                  <th className="p-3 w-40">Endpoint</th>
                </tr>
              </thead>
              <tbody>
                {findings.map(f => (
                  <tr 
                    key={f.id}
                    onClick={() => setSelectedFinding(f)}
                    className={`border-b border-zinc-800/60 hover:bg-zinc-800/30 cursor-pointer transition ${
                      selectedFinding?.id === f.id ? 'bg-rose-500/5' : ''
                    }`}
                  >
                    <td className="p-3 font-semibold text-zinc-200">{f.title}</td>
                    <td className="p-3 text-zinc-400">{f.vulnerabilityType}</td>
                    <td className="p-3">
                      <span className={`px-2.5 py-0.5 rounded border text-[9px] font-bold tracking-wider ${
                        f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400 shadow-[0_0_8px_rgba(244,63,94,0.05)]' :
                        f.severity === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                        'bg-zinc-800 border-zinc-700 text-zinc-400'
                      }`}>{f.severity}</span>
                    </td>
                    <td className="p-3 text-zinc-500 truncate max-w-[200px]">{f.endpoint}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Finding Detail Pane */}
      <div className="w-[450px] border border-zinc-800 bg-zinc-950 rounded-xl flex flex-col overflow-hidden shrink-0">
        {selectedFinding ? (
          <div className="flex-1 p-6 overflow-y-auto space-y-6">
            <div className="border-b border-zinc-800 pb-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${
                  selectedFinding.severity === 'HIGH' || selectedFinding.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' :
                  selectedFinding.severity === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                  'bg-zinc-800 border-zinc-700 text-zinc-400'
                }`}>{selectedFinding.severity}</span>
                <span className="text-[10px] text-zinc-500">{selectedFinding.createdAt}</span>
              </div>
              <h4 className="font-semibold text-sm text-zinc-100 leading-snug">{selectedFinding.title}</h4>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-[10px] font-mono text-zinc-500 block mb-1">VULNERABILITY TYPE</span>
                <span className="text-xs text-zinc-300 font-mono">{selectedFinding.vulnerabilityType}</span>
              </div>

              <div>
                <span className="text-[10px] font-mono text-zinc-500 block mb-1">AFFECTED ENDPOINT</span>
                <span className="text-xs text-zinc-300 font-mono break-all">{selectedFinding.endpoint}</span>
              </div>

              <div>
                <span className="text-[10px] font-mono text-zinc-500 block mb-2">DESCRIPTION & REMEDIATION</span>
                <p className="text-xs text-zinc-400 leading-relaxed bg-zinc-900/40 p-4 border border-zinc-850 rounded-lg whitespace-pre-wrap">{selectedFinding.description}</p>
              </div>

              {selectedFinding.payload && (
                <div>
                  <span className="text-[10px] font-mono text-zinc-500 block mb-1">EXPLOITATION EVIDENCE / PAYLOAD</span>
                  <pre className="font-mono text-xs bg-zinc-950 border border-zinc-800 rounded p-3 text-amber-300 overflow-x-auto">{selectedFinding.payload}</pre>
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center text-zinc-600 text-xs italic">
            Select a finding item to view audit evidence details.
          </div>
        )}
      </div>
    </div>
  )
}
