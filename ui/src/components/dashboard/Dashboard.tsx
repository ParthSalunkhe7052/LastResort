import React, { useState, useEffect, useRef } from 'react'
import { 
  Terminal, Shield, Play, Cpu, ChevronDown, ChevronRight, 
  Tv, FileText, ArrowLeft, ArrowRight, ArrowUpRight,
  Brain, History, Flame, Activity, CheckCircle2, AlertTriangle, Compass,
  Database, AlertCircle, ShieldAlert, Award
} from 'lucide-react'
import type { FindingRecord } from '../findings/FindingsBrowser'

interface ScanEventRecord {
  time: string
  type: string
  message: string
}

interface ScanRecord {
  id: string
  targetUrl: string
  status: string
  progress: number
  profile: string
}

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

interface DashboardProps {
  targetUrl: string
  setTargetUrl: (url: string) => void
  goDaemonStatus: string
  isStartingScan: boolean
  handleStartScan: (e: React.FormEvent) => void
  events: ScanEventRecord[]
  scans: ScanRecord[]
  setActiveScanId: (id: string) => void
  subscribeToEvents: (id: string) => void
  scanModules: any[]
  activeScanId: string | null
  findings: FindingRecord[]
  liveScreenshot: string | null
  performanceMetrics: any
  verifications?: StoredVerification[]
  reportUrl?: string | null
}

interface ParsedEvent {
  time: string
  type: 'thought' | 'decision' | 'memory-load' | 'memory-replay' | 'memory-success' | 'memory-fail' | 'heal' | 'exploit-success' | 'exploit-fail' | 'error' | 'finding' | 'phase-start' | 'phase-complete' | 'system' | 'agent-generic'
  message: string
}

export default function Dashboard({
  targetUrl,
  setTargetUrl,
  goDaemonStatus,
  isStartingScan,
  handleStartScan,
  events,
  scans,
  setActiveScanId,
  subscribeToEvents,
  scanModules,
  activeScanId,
  findings,
  liveScreenshot,
  performanceMetrics,
  verifications = [],
  reportUrl = null
}: DashboardProps) {
  const [authCookie, setAuthCookie] = useState('')
  
  // Timeline Scrubber States
  const [browserHistory, setBrowserHistory] = useState<{screenshot: string; time: string; action: string}[]>([])
  const [historyIndex, setHistoryIndex] = useState<number>(-1)

  // Collapsible sections
  const [isTerminalExpanded, setIsTerminalExpanded] = useState(false)
  
  // Right panel sub-tab
  const [rightPanelTab, setRightPanelTab] = useState<'attacks' | 'verifications' | 'modules' | 'report'>('attacks')

  // Log auto-scroll ref
  const thoughtsEndRef = useRef<HTMLDivElement>(null)
  const terminalEndRef = useRef<HTMLDivElement>(null)

  // Add new frames to history as they stream in
  useEffect(() => {
    if (liveScreenshot) {
      setBrowserHistory(prev => {
        // Prevent adding duplicate consecutive frames
        if (prev.length > 0 && prev[prev.length - 1].screenshot === liveScreenshot) {
          return prev
        }
        const actionMsg = events.length > 0 ? events[0].message : "Navigating target"
        return [...prev, {
          screenshot: liveScreenshot,
          time: new Date().toLocaleTimeString(),
          action: actionMsg
        }]
      })
    }
  }, [liveScreenshot])

  // Automatically update the view index to show the latest frame
  useEffect(() => {
    if (browserHistory.length > 0) {
      setHistoryIndex(browserHistory.length - 1)
    }
  }, [browserHistory.length])

  // Clear state when switching active scans
  useEffect(() => {
    if (!activeScanId) {
      setBrowserHistory([])
      setHistoryIndex(-1)
    }
  }, [activeScanId])

  // Auto-switch to report tab when it arrives
  useEffect(() => {
    if (reportUrl) {
      setRightPanelTab('report')
    }
  }, [reportUrl])

  // Auto-scroll thought stream
  useEffect(() => {
    if (thoughtsEndRef.current) {
      thoughtsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events])

  // Auto-scroll terminal
  useEffect(() => {
    if (isTerminalExpanded && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, isTerminalExpanded])

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

  // Event parsing lists
  const agentEvents = events
    .map(e => parseEvent(e))
    .filter(e => e.type !== 'system' && e.type !== 'agent-generic')
    .reverse() // show in chronological order flowing downwards

  const liveVerifiedFindings = findings.filter(f => f.scanId === activeScanId && !f.isFalsePositive)

  // Renders the initial Landing Setup Screen
  if (!activeScanId) {
    return (
      <div className="flex flex-col items-center justify-center flex-1 max-w-xl mx-auto space-y-8 py-16 px-4">
        <div className="text-center space-y-3">
          <div className="inline-flex p-4 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-500 animate-pulse">
            <Cpu className="w-8 h-8" />
          </div>
          <h2 className="text-xl font-bold tracking-widest font-mono text-zinc-100 uppercase">LastResort Rig</h2>
          <p className="text-xs text-zinc-500 font-mono">Autonomous state-aware browser pentester</p>
        </div>

        <form onSubmit={handleStartScan} className="w-full bg-zinc-900/30 border border-zinc-850 rounded-xl p-8 space-y-6 backdrop-blur-sm shadow-2xl">
          <div className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono text-zinc-500 mb-1.5 uppercase tracking-wider">Target Endpoint URL</label>
              <input
                type="url"
                required
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 rounded-lg px-4 py-3.5 text-zinc-100 font-mono text-xs focus:outline-none focus:border-amber-500 transition shadow-inner"
                placeholder="https://example.com"
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono text-zinc-500 mb-1.5 uppercase tracking-wider">Session Authentication Cookie (Optional)</label>
              <input
                type="text"
                value={authCookie}
                onChange={e => setAuthCookie(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-850 rounded-lg px-4 py-3 text-zinc-100 font-mono text-xs focus:outline-none focus:border-amber-500 transition"
                placeholder="sessionid=abc123xyz; role=user"
              />
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={goDaemonStatus !== 'connected' || isStartingScan}
                className="w-full flex items-center justify-center space-x-2 bg-amber-500 hover:bg-amber-600 disabled:bg-zinc-850 disabled:text-zinc-600 disabled:border-transparent text-zinc-950 py-3.5 rounded-lg font-semibold transition tracking-wide cursor-pointer disabled:cursor-not-allowed border border-amber-400 font-mono text-xs shadow-[0_0_20px_rgba(245,158,11,0.15)]"
              >
                <Play className="w-3.5 h-3.5 fill-zinc-950" />
                <span className="uppercase">{isStartingScan ? 'Spawning Agent Core...' : 'Launch Simulation'}</span>
              </button>
            </div>
          </div>

          <div className="border-t border-zinc-850 pt-4 flex items-center justify-between text-[10px] text-zinc-500 font-mono">
            <span>Daemon connection: <span className="text-emerald-500 font-bold uppercase">{goDaemonStatus}</span></span>
            <span>Real-time spectator engine ready</span>
          </div>
        </form>

        {/* Historical Scans */}
        {scans.length > 0 && (
          <div className="w-full space-y-3">
            <h4 className="text-[10px] font-mono text-zinc-500 uppercase tracking-widest flex items-center space-x-1.5">
              <span>Simulation History ({scans.length})</span>
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {scans.slice(0, 4).map((s, idx) => (
                <div
                  key={idx}
                  onClick={() => {
                    setActiveScanId(s.id);
                    subscribeToEvents(s.id);
                  }}
                  className="p-4 border border-zinc-900 bg-zinc-900/10 hover:border-zinc-850 hover:bg-zinc-900/30 rounded-xl cursor-pointer transition flex flex-col justify-between space-y-1.5 font-mono text-xs border-l-2 border-l-amber-500/60"
                >
                  <span className="text-zinc-200 truncate font-semibold text-amber-500">{s.targetUrl}</span>
                  <div className="flex items-center justify-between text-[10px] text-zinc-500">
                    <span>ID: {s.id.slice(0, 8)}</span>
                    <span className="text-zinc-400 font-semibold">{s.status.replace('SCAN_STATUS_', '')}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  const currentFrame = historyIndex >= 0 && historyIndex < browserHistory.length ? browserHistory[historyIndex] : null

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-zinc-950 text-zinc-300">
      
      {/* Simulation Workspace Panel */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* LEFT COLUMN: Spectator Live Browser Panel */}
        <div className="flex-[1.3] p-5 flex flex-col h-full bg-zinc-950 overflow-hidden border-r border-zinc-900/80">
          
          {/* Mock Browser Header */}
          <div className="flex-1 flex flex-col border border-zinc-850 rounded-xl overflow-hidden bg-zinc-900/5 shadow-2xl relative">
            
            {/* Browser Nav Controls */}
            <div className="bg-zinc-900/90 border-b border-zinc-850 px-4 py-3 flex items-center space-x-3 shrink-0">
              <div className="flex space-x-1.5 shrink-0">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500/80" />
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/80" />
              </div>
              
              <div className="flex items-center space-x-2 text-zinc-500 text-xs">
                <ArrowLeft className="w-3.5 h-3.5 cursor-not-allowed" />
                <ArrowRight className="w-3.5 h-3.5 cursor-not-allowed" />
              </div>
              
              <div className="w-full bg-zinc-950 border border-zinc-850/60 rounded-lg px-3 py-1.5 text-[11px] text-zinc-400 font-mono truncate select-all">
                {targetUrl}
              </div>
            </div>

            {/* Browser Window Screen Area */}
            <div className="flex-1 bg-zinc-950 flex items-center justify-center p-4 relative overflow-hidden">
              {currentFrame ? (
                <div className="w-full h-full flex items-center justify-center relative">
                  <img
                    src={currentFrame.screenshot}
                    alt="Active Spectator Window Frame"
                    className="max-w-full max-h-full object-contain rounded-md border border-zinc-800 shadow-xl"
                  />
                  {/* Realtime Stream Info overlay tag */}
                  <div className="absolute top-4 right-4 bg-zinc-950/80 border border-zinc-800/80 text-[9px] font-mono text-zinc-400 px-2 py-1 rounded shadow-lg backdrop-blur-sm">
                    Frame loaded: {currentFrame.time}
                  </div>
                </div>
              ) : (
                <div className="text-center space-y-4 flex flex-col items-center">
                  <div className="w-8 h-8 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
                  <span className="text-xs font-mono text-zinc-600">Awaiting Browser Session Stream...</span>
                </div>
              )}
            </div>

            {/* TIMELINE SCRUBBER CONTROLS */}
            {browserHistory.length > 0 && (
              <div className="bg-zinc-900/60 border-t border-zinc-850 px-6 py-3.5 flex flex-col space-y-2.5 shrink-0">
                <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                  <div className="flex items-center space-x-2">
                    <Tv className="w-3.5 h-3.5 text-amber-500" />
                    <span className="font-bold tracking-wider uppercase">Browser Timeline</span>
                  </div>
                  <span className="text-zinc-500">Frame {historyIndex + 1} / {browserHistory.length}</span>
                </div>

                <div className="flex items-center space-x-4">
                  {/* Step Back button */}
                  <button
                    disabled={historyIndex <= 0}
                    onClick={() => setHistoryIndex(prev => prev - 1)}
                    className="p-1 bg-zinc-950 border border-zinc-800 rounded hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-zinc-950 transition cursor-pointer text-zinc-400"
                  >
                    <ArrowLeft className="w-4 h-4" />
                  </button>

                  {/* Slider scrub line */}
                  <input
                    type="range"
                    min="0"
                    max={browserHistory.length - 1}
                    value={historyIndex}
                    onChange={e => setHistoryIndex(Number(e.target.value))}
                    className="flex-1 accent-amber-500 bg-zinc-950 h-1 rounded-lg cursor-pointer appearance-none border border-zinc-800"
                  />

                  {/* Step Forward button */}
                  <button
                    disabled={historyIndex >= browserHistory.length - 1}
                    onClick={() => setHistoryIndex(prev => prev + 1)}
                    className="p-1 bg-zinc-950 border border-zinc-800 rounded hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-zinc-950 transition cursor-pointer text-zinc-400"
                  >
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>

                {/* Selected Frame Action Tooltip Description */}
                {currentFrame && (
                  <div className="bg-zinc-950/60 border border-zinc-900 p-2 rounded text-[10px] font-mono text-zinc-400 flex items-center justify-between">
                    <span className="truncate text-zinc-400">Action: <strong className="text-zinc-200 font-semibold">{currentFrame.action}</strong></span>
                    <span className="text-zinc-650 shrink-0 pl-4">{currentFrame.time}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        
        {/* CENTER COLUMN: Cognitive Agent Activity Feed */}
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
                // Determine styling based on type
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
                    icon = <Flame className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
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

        {/* RIGHT COLUMN: Verdict findings and evidence inspector */}
        <div className="w-[420px] border-l border-zinc-900 bg-zinc-950/20 p-5 flex flex-col h-full shrink-0 overflow-hidden">
          
          {/* Right Panel Sub-tab Headers */}
          <div className="flex border-b border-zinc-900 shrink-0 text-[10px] font-mono gap-1">
            <button
              onClick={() => setRightPanelTab('attacks')}
              className={`flex-1 pb-2 font-bold tracking-wider uppercase border-b-2 transition cursor-pointer text-center ${
                rightPanelTab === 'attacks' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Manual Proofs ({liveVerifiedFindings.length})
            </button>
            <button
              onClick={() => setRightPanelTab('verifications')}
              className={`flex-1 pb-2 font-bold tracking-wider uppercase border-b-2 transition cursor-pointer text-center ${
                rightPanelTab === 'verifications' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              AI pipeline
            </button>
            <button
              onClick={() => setRightPanelTab('modules')}
              className={`flex-1 pb-2 font-bold tracking-wider uppercase border-b-2 transition cursor-pointer text-center ${
                rightPanelTab === 'modules' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Status
            </button>
            <button
              onClick={() => setRightPanelTab('report')}
              className={`flex-1 pb-2 font-bold tracking-wider uppercase border-b-2 transition cursor-pointer text-center ${
                rightPanelTab === 'report' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Report
            </button>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar pt-4 space-y-4">
            
            {/* MANUAL REPRODUCTIONS / ATTACKS TAB */}
            {rightPanelTab === 'attacks' && (
              liveVerifiedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-2">
                  <Shield className="w-8 h-8 text-zinc-800" />
                  <p className="font-mono text-[11px]">No verified exploits found yet.</p>
                </div>
              ) : (
                liveVerifiedFindings.map((f) => (
                  <div 
                    key={f.id} 
                    className="border border-zinc-850 bg-zinc-900/10 rounded-xl p-4.5 relative overflow-hidden shadow-lg border-l-4 border-l-amber-500/80"
                  >
                    <div className="flex items-center justify-between mb-2.5">
                      <span className="px-2 py-0.5 rounded border text-[9px] font-bold font-mono tracking-wider bg-amber-500/10 border-amber-500/20 text-amber-400 uppercase">
                        Manual Verification Proof
                      </span>
                      <span className="text-[10px] text-rose-500 font-mono font-bold uppercase tracking-wider">{f.vulnerabilityType || 'VULN'}</span>
                    </div>
                    
                    <h4 className="text-xs font-bold text-zinc-100 font-sans mb-3">{f.title}</h4>
                    
                    <div className="space-y-4.5 font-mono text-[10px] text-zinc-300">
                      {(() => {
                        const type = (f.vulnerabilityType || '').toUpperCase();
                        
                        if (type.includes('SQL') || type.includes('INJECTION')) {
                          const paramMatch = f.title.match(/-\s*(.+)$/);
                          const paramName = paramMatch ? paramMatch[1] : 'vulnerable input field';
                          return (
                            <>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">1. Target Page</span>
                                <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-sky-400 text-[9.5px]">
                                  {f.endpoint}
                                </div>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">2. Vulnerable Parameter</span>
                                <p className="text-zinc-400">Locate input corresponding to: <strong className="text-zinc-200">"{paramName}"</strong></p>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">3. SQL Injection Payload</span>
                                <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-emerald-400 font-bold text-[9.5px]">
                                  {f.payload || "' OR '1'='1"}
                                </div>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">4. Confirm Leak</span>
                                <p className="text-zinc-400">Submit the payload. Look for SQL database syntax errors or authentication bypass confirmation.</p>
                              </div>
                            </>
                          );
                        } else if (type.includes('XSS') || type.includes('SCRIPT')) {
                          const paramMatch = f.title.match(/parameter:\s*(.+)$/i) || f.title.match(/-\s*(.+)$/);
                          const paramName = paramMatch ? paramMatch[1] : 'vulnerable parameter';
                          return (
                            <>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">1. Target Page</span>
                                <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-sky-400 text-[9.5px]">
                                  {f.endpoint}
                                </div>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">2. Parameter to Target</span>
                                <p className="text-zinc-400">Target parameter or field: <strong className="text-zinc-200">"{paramName}"</strong></p>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">3. XSS Payload</span>
                                <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-emerald-400 font-bold text-[9.5px]">
                                  {f.payload || "<script>alert('XSS')</script>"}
                                </div>
                              </div>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">4. Verification</span>
                                <p className="text-zinc-400">Trigger request with payload. Verify if browser fires a popup box or script executes inside page DOM.</p>
                              </div>
                            </>
                          );
                        } else {
                          return (
                            <>
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">1. Target Link</span>
                                <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-sky-400 text-[9.5px]">
                                  {f.endpoint}
                                </div>
                              </div>
                              {f.payload && (
                                <div>
                                  <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">2. Payload</span>
                                  <div className="bg-zinc-950 p-2 rounded border border-zinc-900 break-all select-all text-emerald-400 text-[9.5px]">
                                    {f.payload}
                                  </div>
                                </div>
                              )}
                              <div>
                                <span className="text-amber-500 font-bold uppercase tracking-wider block mb-1">3. Replication</span>
                                <p className="text-zinc-400">Submit and observe differences in response codes or security headers bypass.</p>
                              </div>
                            </>
                          );
                        }
                      })()}
                    </div>
                  </div>
                ))
              )
            )}

            {/* AI PIPELINE / VERIFICATIONS TAB */}
            {rightPanelTab === 'verifications' && (
              verifications.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-2">
                  <Activity className="w-8 h-8 text-zinc-800" />
                  <p className="font-mono text-[11px]">No verification pipeline tasks active yet.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {verifications.map((v) => (
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
            )}

            {/* STATUS / SCAN MODULES TAB */}
            {rightPanelTab === 'modules' && (
              <div className="space-y-4">
                {/* Active scan status */}
                <div className="bg-zinc-900/20 border border-zinc-900 p-4 rounded-xl space-y-3 font-mono text-[10.5px]">
                  <span className="text-zinc-400 font-bold uppercase tracking-wider block text-[9.5px]">Performance Metrics</span>
                  <div className="grid grid-cols-2 gap-3 text-zinc-300">
                    <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
                      <span className="text-zinc-500 block text-[8px] mb-0.5">Visits / Crawl</span>
                      <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.visited_pages || 0} pages</span>
                    </div>
                    <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
                      <span className="text-zinc-500 block text-[8px] mb-0.5">HTTP Fuzz Req</span>
                      <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.fuzz_requests || 0} reqs</span>
                    </div>
                    <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
                      <span className="text-zinc-500 block text-[8px] mb-0.5">Scan Duration</span>
                      <span className="font-bold text-amber-500 text-xs">{performanceMetrics?.elapsed_seconds || 0}s</span>
                    </div>
                    <div className="bg-zinc-950 p-2.5 rounded border border-zinc-900">
                      <span className="text-zinc-500 block text-[8px] mb-0.5">Verification Loop</span>
                      <span className="font-bold text-amber-500 text-xs">{verifications.length} verified</span>
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
                        <span className="font-bold">{m.module_name}</span>
                      </div>
                      <span className="text-[9px] uppercase tracking-widest font-semibold">{m.status}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* REPORT SUB-TAB */}
            {rightPanelTab === 'report' && (
              reportUrl ? (
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
              ) : (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-600 h-full space-y-2">
                  <FileText className="w-8 h-8 text-zinc-800" />
                  <p className="font-mono text-[11px]">Report will be available after scan completion.</p>
                </div>
              )
            )}
          </div>
        </div>
      </div>

      {/* COLLAPSIBLE TERMINAL CONSOLE PANEL */}
      <div className="border-t border-zinc-900 bg-zinc-950 shrink-0">
        
        {/* Toggle Bar */}
        <div 
          onClick={() => setIsTerminalExpanded(!isTerminalExpanded)}
          className="px-6 py-2.5 flex items-center justify-between cursor-pointer hover:bg-zinc-900/60 transition"
        >
          <div className="flex items-center space-x-2 text-xs font-mono text-zinc-400">
            <Terminal className="w-4 h-4 text-amber-500" />
            <span className="font-bold tracking-wider uppercase">Raw Engine Console</span>
          </div>
          {isTerminalExpanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
        </div>

        {/* Console Text Window */}
        {isTerminalExpanded && (
          <div className="h-44 overflow-y-auto bg-black/60 p-5 font-mono text-[10px] text-zinc-400 space-y-1.5 custom-scrollbar border-t border-zinc-900">
            {events
              .filter(e => {
                if (!e.message) return false;
                const msg = e.message.toLowerCase();
                // Filter out verbose/spammy entries
                if (msg.includes('failed to load resource: net::err')) return false;
                if (msg.includes('browser.screenshot')) return false;
                // Keep all LLM, Recon, Orchestrator, memory, and error events
                return true;
              })
              .map((e, idx) => (
                <div key={idx} className="flex items-start space-x-3 text-zinc-500">
                  <span className="shrink-0 text-zinc-650">{e.time}</span>
                  <span className="shrink-0 text-zinc-650 bg-zinc-900/40 px-1 rounded">[{e.type.toUpperCase()}]</span>
                  <span className="break-all text-zinc-350">{e.message}</span>
                </div>
              ))}
            <div ref={terminalEndRef} />
          </div>
        )}
      </div>

    </div>
  )
}
