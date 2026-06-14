import { useState, useEffect } from 'react'
import { AlertTriangle, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react'
import { BASE_URL } from '../../api/client'

interface Finding {
  id: string
  title: string
  severity: string
  vulnerability_type: string
  endpoint: string
  payload: string
  description: string
  confidence: number
}

interface FindingsSummaryProps {
  scanId: string
}

const SEVERITY_CONFIG: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  HIGH: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  LOW: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  INFO: { bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
}

export default function FindingsSummary({ scanId }: FindingsSummaryProps) {
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(true)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  useEffect(() => {
    fetchFindings()
  }, [scanId])

  const fetchFindings = async () => {
    try {
      const res = await fetch(`${BASE_URL}/api/v1/scan/findings?scan_id=${scanId}`)
      if (res.ok) {
        const data = await res.json()
        setFindings(data.findings || [])
      }
    } catch (err) {
      console.error('Failed to fetch findings:', err)
    } finally {
      setLoading(false)
    }
  }

  const severityCounts = findings.reduce((acc, f) => {
    const s = f.severity?.toUpperCase() || 'INFO'
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  if (loading) {
    return (
      <div className="p-4 text-zinc-600 text-[10px] font-mono uppercase tracking-widest">
        Loading findings...
      </div>
    )
  }

  if (findings.length === 0) {
    return (
      <div className="p-4 text-center text-zinc-600">
        <AlertTriangle className="w-6 h-6 mx-auto mb-2 opacity-30" />
        <p className="text-[10px] font-mono uppercase tracking-widest">No findings yet</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Severity Breakdown */}
      <div className="flex items-center space-x-2 text-amber-500 mb-3">
        <AlertTriangle className="w-4 h-4" />
        <span className="text-[10px] font-mono uppercase tracking-widest font-bold">Findings Summary</span>
      </div>

      <div className="grid grid-cols-5 gap-1">
        {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(severity => {
          const count = severityCounts[severity] || 0
          const config = SEVERITY_CONFIG[severity]
          return (
            <div key={severity} className={`${config.bg} ${config.border} border rounded p-2 text-center`}>
              <div className={`text-lg font-bold ${config.text}`}>{count}</div>
              <div className="text-[8px] font-mono uppercase tracking-wider text-zinc-500">{severity}</div>
            </div>
          )
        })}
      </div>

      {/* Findings List */}
      <div className="space-y-1 mt-4">
        {findings.slice(0, 10).map((finding) => {
          const config = SEVERITY_CONFIG[finding.severity?.toUpperCase()] || SEVERITY_CONFIG.INFO
          const isExpanded = expandedId === finding.id
          return (
            <div key={finding.id} className={`${config.bg} border ${config.border} rounded`}>
              <button
                onClick={() => setExpandedId(isExpanded ? null : finding.id)}
                className="w-full flex items-center justify-between p-2 text-left hover:opacity-80 transition"
              >
                <div className="flex items-center space-x-2">
                  <span className={`text-[9px] font-mono font-bold ${config.text} px-1.5 py-0.5 rounded bg-black/20`}>
                    {finding.severity}
                  </span>
                  <span className="text-[11px] font-mono text-zinc-300 truncate max-w-[200px]">
                    {finding.title}
                  </span>
                </div>
                {isExpanded ? (
                  <ChevronDown className="w-3 h-3 text-zinc-500" />
                ) : (
                  <ChevronRight className="w-3 h-3 text-zinc-500" />
                )}
              </button>
              {isExpanded && (
                <div className="px-2 pb-2 space-y-1 text-[10px] font-mono text-zinc-400 border-t border-zinc-800/50 pt-2">
                  <div><span className="text-zinc-600">Type:</span> {finding.vulnerability_type}</div>
                  <div><span className="text-zinc-600">URL:</span> <span className="text-amber-400/80 break-all">{finding.endpoint}</span></div>
                  {finding.payload && (
                    <div><span className="text-zinc-600">Payload:</span> <code className="text-amber-400 bg-amber-500/10 px-1 rounded">{finding.payload}</code></div>
                  )}
                  {finding.description && (
                    <div className="text-zinc-500 mt-1">{finding.description.substring(0, 200)}...</div>
                  )}
                  <div className="flex items-center space-x-1 mt-1">
                    <a
                      href={finding.endpoint}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-amber-500/70 hover:text-amber-400 flex items-center space-x-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      <span>Open in browser</span>
                    </a>
                  </div>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
