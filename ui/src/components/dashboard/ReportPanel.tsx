import { FileText, ArrowUpRight } from 'lucide-react'

interface ReportPanelProps {
  reportUrl: string | null
}

export default function ReportPanel({ reportUrl }: ReportPanelProps) {
  if (!reportUrl) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-2">
        <FileText className="w-8 h-8 text-zinc-800" />
        <p className="font-mono text-[11px]">Report will be available after scan completion.</p>
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full space-y-4">
      <div className="flex items-center justify-between px-1">
        <span className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest">Final Assessment Report</span>
        <a 
          href={reportUrl} 
          target="_blank" 
          rel="noopener noreferrer"
          className="text-[10px] font-mono text-amber-500 hover:text-amber-400 flex items-center space-x-1"
        >
          <span>Open External</span>
          <ArrowUpRight className="w-3.5 h-3.5" />
        </a>
      </div>
      <iframe 
        src={reportUrl} 
        className="flex-1 w-full bg-white rounded-lg border border-zinc-800 min-h-[500px]"
        title="Scan Report"
      />
    </div>
  )
}
