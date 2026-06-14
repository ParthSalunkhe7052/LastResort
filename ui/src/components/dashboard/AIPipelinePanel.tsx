import { Activity, Award } from 'lucide-react'

interface StoredVerification {
  id: string
  finding_id: string
  scan_id: string
  verified: boolean
  confidence: number
  method: string
  summary: string
  artifacts_json: string
  endpoint_url: string
  payload: string
  created_at: string
}

interface AIPipelinePanelProps {
  verifications: StoredVerification[]
}

export default function AIPipelinePanel({ verifications }: AIPipelinePanelProps) {
  if (verifications.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-2">
        <Activity className="w-8 h-8 text-zinc-800" />
        <p className="font-mono text-[11px]">No verification pipeline tasks active yet.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {verifications.map(v => (
        <div 
          key={v.id} 
          className={`border rounded-xl p-4 font-mono text-[10px] space-y-3.5 transition-all duration-300 ${
            v.verified 
              ? 'border-rose-900/50 bg-rose-950/5 text-rose-100 shadow-[0_0_8px_rgba(244,63,94,0.04)] border-l-4 border-l-rose-500'
              : 'border-zinc-850 bg-zinc-900/10 text-zinc-400 border-l-4 border-l-zinc-600'
          }`}
        >
          <div className="flex items-center justify-between">
            <span className="flex items-center space-x-1 font-bold text-zinc-300">
              <Award className={`w-3.5 h-3.5 ${v.verified ? 'text-rose-400' : 'text-zinc-500'}`} />
              <span>AI VERDICT</span>
            </span>
            <span className={`px-2 py-0.5 rounded text-[8px] font-bold uppercase ${
              v.verified ? 'bg-rose-500/10 border border-rose-500/20 text-rose-400' : 'bg-zinc-800 text-zinc-500'
            }`}>
              {v.verified ? 'Verified Exploit' : 'False Positive'}
            </span>
          </div>

          <div className="space-y-2 leading-relaxed">
            <div className="text-zinc-350">
              <span className="text-zinc-500 uppercase tracking-wider block text-[8px] mb-0.5">Vector Endpoint</span>
              <span className="break-all">{v.endpoint_url}</span>
            </div>

            <div className="text-zinc-350">
              <span className="text-zinc-500 uppercase tracking-wider block text-[8px] mb-0.5">Verification Method</span>
              <span className="bg-zinc-900 px-1.5 py-0.5 rounded text-[8px]">{v.method}</span>
            </div>

            <div className="text-zinc-350">
              <span className="text-zinc-500 uppercase tracking-wider block text-[8px] mb-0.5">Confidence</span>
              <span>{(v.confidence * 100).toFixed(0)}% Match</span>
            </div>

            <div className="text-zinc-300 bg-black/40 p-2.5 rounded border border-zinc-900/60 text-[10px]">
              <span className="text-amber-500/80 font-bold uppercase tracking-wider block text-[8.5px] mb-1.5">AI Proof Summary</span>
              {v.summary}
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
