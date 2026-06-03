import { useState, useEffect } from 'react'
import { FileText, RefreshCw, Eye } from 'lucide-react'
import { client } from '../../api/client'

interface ReportRecord {
  id: string
  scanId: string
  format: string
  path: string
  title: string
  createdAt: string
}

interface ReportGeneratorProps {
  activeScanId: string | null
}

export default function ReportGenerator({ activeScanId }: ReportGeneratorProps) {
  const [reports, setReports] = useState<ReportRecord[]>([])
  const [isGenerating, setIsGenerating] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const fetchReports = async () => {
    if (!activeScanId) return
    setIsLoading(true)
    try {
      const res = await client.listReports({ scanId: activeScanId })
      const records = res.reports.map(r => ({
        id: r.id,
        scanId: r.scanId,
        format: r.format,
        path: r.path,
        title: r.title,
        createdAt: new Date(r.createdAt).toLocaleString()
      }))
      setReports(records)
    } catch (err) {
      console.error('Failed to list reports:', err)
    } finally {
      setIsLoading(false)
    }
  }

  const handleGenerateReport = async () => {
    if (!activeScanId) return
    setIsGenerating(true)
    try {
      await client.generateReport({ scanId: activeScanId })
      await fetchReports()
    } catch (err) {
      console.error('Failed to generate report:', err)
    } finally {
      setIsGenerating(false)
    }
  }

  useEffect(() => {
    if (activeScanId) {
      fetchReports()
    }
  }, [activeScanId])

  const getReportUrl = () => {
    // Convert local Windows file paths or absolute system paths to served url
    // Go server serves `./data/reports` directory on `http://localhost:8443/reports/`
    return `http://127.0.0.1:8443/reports/${activeScanId}/report.html`
  }

  return (
    <div className="max-w-4xl border border-zinc-800 bg-zinc-900/30 rounded-xl p-8 space-y-6">
      <div className="flex items-center justify-between border-b border-zinc-850 pb-4">
        <h3 className="font-semibold text-lg flex items-center space-x-2 text-zinc-100">
          <FileText className="w-6 h-6 text-amber-500" />
          <span>Report Generator</span>
        </h3>
        {activeScanId && (
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="bg-amber-500 hover:bg-amber-600 disabled:bg-zinc-800 disabled:text-zinc-600 text-zinc-950 font-mono text-xs px-4 py-2 rounded font-bold shadow-[0_0_10px_rgba(245,158,11,0.1)] border border-amber-400 cursor-pointer flex items-center space-x-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? 'Generating Report...' : 'Compile New Report'}</span>
          </button>
        )}
      </div>

      {!activeScanId ? (
        <div className="text-zinc-500 text-xs italic">Please select or run a scan from the Assessment Dashboard first to compile reports.</div>
      ) : (
        <div className="space-y-6">
          <p className="text-xs text-zinc-400 leading-relaxed">
            Generate and export comprehensive security reports for Scan ID <span className="font-mono text-amber-500">{activeScanId}</span>. 
            Reports include technology profiles, vulnerability listings, details, remediations, and evidence.
          </p>

          <div className="space-y-4">
            <h4 className="text-xs font-mono text-zinc-500 uppercase tracking-wider">Generated Report Exports</h4>
            {isLoading && reports.length === 0 ? (
              <div className="text-xs text-zinc-500">Loading reports...</div>
            ) : reports.length === 0 ? (
              <div className="text-xs text-zinc-500 italic">No reports compiled yet for this scan. Click 'Compile New Report' above to build HTML and Markdown logs.</div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {reports.map(r => (
                  <div key={r.id} className="p-4 border border-zinc-800 bg-zinc-950/60 rounded-xl flex items-center justify-between space-x-4">
                    <div className="space-y-1 min-w-0">
                      <div className="text-xs font-semibold text-zinc-200 truncate">{r.title}</div>
                      <div className="text-[10px] text-zinc-500 font-mono">Format: <span className="uppercase text-amber-500/80">{r.format}</span> | Created: {r.createdAt}</div>
                    </div>
                    {r.format === 'html' && (
                      <button
                        onClick={() => window.open(getReportUrl(), '_blank')}
                        className="bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 p-2 rounded text-zinc-300 hover:text-zinc-100 transition cursor-pointer"
                        title="View Report in New Tab"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
