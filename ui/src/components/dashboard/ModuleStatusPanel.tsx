import { CheckCircle2 } from 'lucide-react'

interface ModuleStatusPanelProps {
  scanModules: any[]
  performanceMetrics: any
  verificationsCount: number
}

export default function ModuleStatusPanel({
  scanModules,
  performanceMetrics,
  verificationsCount
}: ModuleStatusPanelProps) {
  return (
    <div className="space-y-4">
      {/* Performance Metrics */}
      <div className="bg-zinc-900/20 border border-zinc-900 p-4 rounded-xl space-y-3 font-mono text-[10.5px]">
        <span className="text-zinc-400 font-bold uppercase tracking-wider block text-[9.5px]">Performance Metrics</span>
        <div className="grid grid-cols-2 gap-3 text-zinc-300">
          <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
            <span className="text-zinc-500 block text-[8px] mb-0.5">Visits / Crawl</span>
            <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.pages_crawled || 0} pages</span>
          </div>
          <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
            <span className="text-zinc-500 block text-[8px] mb-0.5">HTTP Fuzz Req</span>
            <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.attack_attempts || 0} reqs</span>
          </div>
          <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
            <span className="text-zinc-500 block text-[8px] mb-0.5">Scan Duration</span>
            <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.scan_duration || 0}s</span>
          </div>
          <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
            <span className="text-zinc-500 block text-[8px] mb-0.5">Verification Loop</span>
            <span className="font-bold text-amber-500 text-xs">{verificationsCount} verified</span>
          </div>
        </div>
      </div>

      {/* Modules progress */}
      <div className="space-y-2.5 font-mono text-[10px]">
        <span className="text-zinc-400 font-bold uppercase tracking-wider block text-[9.5px] px-1 mb-1">Pipeline Engines</span>
        {scanModules.map((m, idx) => (
          <div 
            key={idx}
            className={`p-3 rounded-lg border flex items-center justify-between transition ${
              m.status === 'RUNNING' 
                ? 'border-amber-500/30 bg-amber-500/5 text-amber-400'
                : m.status === 'COMPLETED'
                ? 'border-zinc-900/60 bg-zinc-950 text-zinc-400'
                : 'border-zinc-900/30 bg-zinc-950/30 text-zinc-600'
            }`}
          >
            <div className="flex items-center space-x-2">
              {m.status === 'RUNNING' ? (
                <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse shadow-[0_0_6px_#f59e0b]" />
              ) : m.status === 'COMPLETED' ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
              ) : (
                <span className="w-1.5 h-1.5 rounded-full bg-zinc-700" />
              )}
              <span className="font-bold">{m.module_name || m.module}</span>
            </div>
            <span className="text-[9px] uppercase tracking-widest font-semibold">{m.status}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
