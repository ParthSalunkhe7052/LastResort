import type { RefObject } from 'react'
import { 
  Brain, Cpu, Compass, Database, History, 
  CheckCircle2, AlertTriangle, Shield, ShieldAlert, AlertCircle, Activity, Flame
} from 'lucide-react'

interface ScanEventRecord {
  time: string
  type: string
  message: string
}

interface EventTimelineProps {
  events: ScanEventRecord[]
  thoughtsEndRef: RefObject<HTMLDivElement>
}

interface ParsedEvent {
  time: string
  type: 'thought' | 'decision' | 'memory-load' | 'memory-replay' | 'memory-success' | 'memory-fail' | 'heal' | 'exploit-success' | 'exploit-fail' | 'error' | 'finding' | 'phase-start' | 'phase-complete' | 'system' | 'agent-generic'
  message: string
}

export default function EventTimeline({
  events,
  thoughtsEndRef
}: EventTimelineProps) {
  // Parser helper for agent logs
  const parseEvent = (e: ScanEventRecord): ParsedEvent => {
    const msg = e.message || ''
    let type: ParsedEvent['type'] = 'system'
    let cleanMsg = msg
    
    if (msg.startsWith('[AGENT]')) {
      cleanMsg = msg.replace('[AGENT]', '').trim()
      if (cleanMsg.includes('[MEMORY-REPLAY]')) {
        type = 'memory-replay'
        cleanMsg = cleanMsg.replace('[MEMORY-REPLAY]', '').trim()
      } else if (cleanMsg.includes('[MEMORY-SUCCESS]')) {
        type = 'memory-success'
        cleanMsg = cleanMsg.replace('[MEMORY-SUCCESS]', '').trim()
      } else if (cleanMsg.includes('[MEMORY-FAIL]')) {
        type = 'memory-fail'
        cleanMsg = cleanMsg.replace('[MEMORY-FAIL]', '').trim()
      } else if (cleanMsg.includes('[MEMORY]')) {
        type = 'memory-load'
        cleanMsg = cleanMsg.replace('[MEMORY]', '').trim()
      } else if (cleanMsg.includes('[HEAL]')) {
        type = 'heal'
        cleanMsg = cleanMsg.replace('[HEAL]', '').trim()
      } else if (cleanMsg.startsWith('Thought:')) {
        type = 'thought'
        cleanMsg = cleanMsg.replace('Thought:', '').trim()
      } else if (cleanMsg.startsWith('Decision:')) {
        type = 'decision'
        cleanMsg = cleanMsg.replace('Decision:', '').trim()
      } else if (cleanMsg.includes('[ERROR]')) {
        type = 'error'
        cleanMsg = cleanMsg.replace('[ERROR]', '').trim()
      } else if (cleanMsg.includes('EXPLOIT SUCCESSFUL!')) {
        type = 'exploit-success'
        cleanMsg = cleanMsg.replace('EXPLOIT SUCCESSFUL!', '').trim()
      } else if (cleanMsg.includes('Exploit failed:')) {
        type = 'exploit-fail'
        cleanMsg = cleanMsg.replace('Exploit failed:', '').trim()
      } else {
        type = 'agent-generic'
      }
    } else if (msg.includes('[FINDING DISCOVERED]')) {
      type = 'finding'
    } else if (msg.includes('Phase [') && msg.includes('started')) {
      type = 'phase-start'
    } else if (msg.includes('Phase [') && msg.includes('completed')) {
      type = 'phase-complete'
    }
    
    return { time: e.time, type, message: cleanMsg }
  }

  const agentEvents = events
    .map(e => parseEvent(e))
    .filter(e => e.type !== 'system' && e.type !== 'agent-generic')
    .reverse() // chronological order

  return (
    <div className="flex-1 border-r border-zinc-900 bg-zinc-950/10 p-5 flex flex-col h-full overflow-hidden">
      <div className="flex items-center space-x-2 pb-4 border-b border-zinc-900 shrink-0 justify-between">
        <div className="flex items-center space-x-2">
          <Brain className="w-4.5 h-4.5 text-amber-500 animate-pulse" />
          <h3 className="font-mono text-xs font-bold tracking-wider uppercase text-zinc-300">Cognitive Stream</h3>
        </div>
        {agentEvents.length > 0 && (
          <span className="text-[10px] font-mono bg-amber-500/10 text-amber-500 border border-amber-500/20 px-2 py-0.5 rounded-full">
            Active Loop
          </span>
        )}
      </div>
      
      <div className="flex-1 overflow-y-auto custom-scrollbar pt-4 space-y-4 font-mono text-[11px] leading-relaxed">
        {agentEvents.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-3">
            <Cpu className="w-8 h-8 text-zinc-800 animate-pulse" />
            <p className="italic">Awaiting autonomous loop signals...</p>
          </div>
        ) : (
          agentEvents.map((e, idx) => {
            let colorClass = 'border-zinc-900/60 bg-zinc-900/10 text-zinc-300'
            let icon = <Cpu className="w-3.5 h-3.5" />
            let tag = 'AGENT'
            
            switch (e.type) {
              case 'thought':
                colorClass = 'border-amber-500/20 bg-amber-500/5 text-amber-100 shadow-[0_0_8px_rgba(245,158,11,0.02)]'
                icon = <Brain className="w-3.5 h-3.5 text-amber-400" />
                tag = 'THOUGHT'
                break
              case 'decision':
                colorClass = 'border-emerald-500/20 bg-emerald-500/5 text-emerald-100'
                icon = <Compass className="w-3.5 h-3.5 text-emerald-400" />
                tag = 'PLAN'
                break
              case 'memory-load':
                colorClass = 'border-indigo-500/25 bg-indigo-500/5 text-indigo-200'
                icon = <Database className="w-3.5 h-3.5 text-indigo-400" />
                tag = 'MEM LOAD'
                break
              case 'memory-replay':
                colorClass = 'border-purple-500/25 bg-purple-500/5 text-purple-200'
                icon = <History className="w-3.5 h-3.5 text-purple-400" />
                tag = 'REPLAY'
                break
              case 'memory-success':
                colorClass = 'border-teal-500/25 bg-teal-500/5 text-teal-200'
                icon = <CheckCircle2 className="w-3.5 h-3.5 text-teal-400" />
                tag = 'MEM SUCCESS'
                break
              case 'memory-fail':
                colorClass = 'border-rose-500/25 bg-rose-500/5 text-rose-200'
                icon = <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                tag = 'MEM FAIL'
                break
              case 'heal':
                colorClass = 'border-cyan-500/25 bg-cyan-500/5 text-cyan-200'
                icon = <Flame className="w-3.5 h-3.5 text-cyan-400 animate-pulse animate-duration-2000" />
                tag = 'HEALING'
                break
              case 'exploit-success':
                colorClass = 'border-rose-600/50 bg-rose-950/25 text-rose-100 shadow-[0_0_12px_rgba(239,68,68,0.12)] border-l-4 border-l-rose-500'
                icon = <Shield className="w-3.5 h-3.5 text-rose-400" />
                tag = 'VERIFIED EXPLOIT'
                break
              case 'exploit-fail':
                colorClass = 'border-zinc-800 bg-zinc-900/30 text-zinc-450'
                icon = <ShieldAlert className="w-3.5 h-3.5 text-zinc-500" />
                tag = 'EXPLOIT FAILED'
                break
              case 'error':
                colorClass = 'border-rose-500/30 bg-rose-500/5 text-rose-100'
                icon = <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
                tag = 'ERROR'
                break
              case 'finding':
                colorClass = 'border-amber-600/35 bg-amber-950/15 text-amber-200'
                icon = <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                tag = 'FUZZ FINDING'
                break
              case 'phase-start':
                colorClass = 'border-blue-500/20 bg-blue-900/5 text-blue-300'
                icon = <Activity className="w-3.5 h-3.5 text-blue-400" />
                tag = 'PHASE IN'
                break
              case 'phase-complete':
                colorClass = 'border-emerald-500/20 bg-emerald-900/5 text-emerald-300'
                icon = <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                tag = 'PHASE OUT'
                break
              default:
                break
            }

            return (
              <div 
                key={idx} 
                className={`p-3.5 rounded-xl border leading-relaxed transition-all duration-300 hover:bg-zinc-900/20 ${colorClass}`}
              >
                <div className="flex items-center justify-between mb-2 text-[9px] text-zinc-500 font-mono">
                  <span className="flex items-center space-x-1.5">
                    {icon}
                    <span className="font-bold tracking-wider">{tag}</span>
                  </span>
                  <span>{e.time}</span>
                </div>
                <p className="whitespace-pre-wrap text-[10.5px] leading-relaxed font-mono">{e.message}</p>
              </div>
            )
          })
        )}
        <div ref={thoughtsEndRef} />
      </div>
    </div>
  )
}
