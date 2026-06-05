import React, { useState, useEffect, useRef } from 'react'
import { 
  Terminal, Shield, Play, Cpu, Sparkles, ChevronDown, ChevronRight, 
  Tv, FileText, ArrowLeft, ArrowRight, ArrowUpRight
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
  activeScanId,
  findings,
  liveScreenshot,
  verifications = [],
  reportUrl = null
}: DashboardProps) {
  const [authCookie, setAuthCookie] = useState('')
  
  // Timeline Scrubber States
  const [browserHistory, setBrowserHistory] = useState<{screenshot: string; time: string; action: string}[]>([])
  const [historyIndex, setHistoryIndex] = useState<number>(-1)

  // Collapsible sections
  const [isTerminalExpanded, setIsTerminalExpanded] = useState(false)
  const [expandedVerificationId, setExpandedVerificationId] = useState<string | null>(null)
  
  // Right panel sub-tab
  const [rightPanelTab, setRightPanelTab] = useState<'findings' | 'evidence' | 'report'>('findings')

  // Log auto-scroll ref
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
      setExpandedVerificationId(null)
    }
  }, [activeScanId])

  // Auto-switch to report tab when it arrives
  useEffect(() => {
    if (reportUrl) {
      setRightPanelTab('report')
    }
  }, [reportUrl])

  // Auto-scroll terminal
  useEffect(() => {
    if (isTerminalExpanded && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [events, isTerminalExpanded])

  // Helpers to parse artifacts
  const parseArtifacts = (jsonStr: string) => {
    try {
      return JSON.parse(jsonStr) || []
    } catch {
      return []
    }
  }

  // Filter findings for verified attacks
  const liveVerifiedFindings = findings.filter(f => f.category === 'VERIFIED_ATTACK')

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

  // Renders the Active Simulation Spectator View
  const currentFrame = historyIndex >= 0 && historyIndex < browserHistory.length ? browserHistory[historyIndex] : null

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-zinc-950 text-zinc-300">
      
      {/* Simulation Workspace Panel */}
      <div className="flex flex-1 overflow-hidden">
        
        {/* LEFT COLUMN: Cognitive Agent Activity Feed */}
        <div className="w-80 border-r border-zinc-900 bg-zinc-950/20 p-5 flex flex-col h-full shrink-0">
          <div className="flex items-center space-x-2 pb-4 border-b border-zinc-900 shrink-0">
            <Sparkles className="w-4 h-4 text-amber-500 animate-pulse" />
            <h3 className="font-mono text-xs font-bold tracking-wider uppercase text-zinc-400">Agent Thoughts</h3>
          </div>
          
          <div className="flex-1 overflow-y-auto custom-scrollbar pt-4 space-y-4 font-mono text-[11px] leading-relaxed">
            {events.length === 0 ? (
              <p className="text-zinc-600 italic">Starting cognitive log stream...</p>
            ) : (
              events
                .filter(e => e.message && (e.message.startsWith('[AGENT]') || e.message.includes('[FINDING')))
                .map((e, idx) => {
                  const isExploit = e.message.includes('[FINDING')
                  const cleanMsg = e.message.replace('[AGENT]', '').trim()
                  return (
                    <div 
                      key={idx} 
                      className={`p-3 rounded-lg border leading-relaxed transition ${
                        isExploit 
                          ? 'bg-rose-950/20 border-rose-900/50 text-rose-300 shadow-[0_0_8px_rgba(244,63,94,0.05)]' 
                          : 'bg-zinc-900/10 border-zinc-900/60 text-zinc-300'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5 text-[9px] text-zinc-500">
                        <span className="flex items-center space-x-1">
                          {isExploit ? (
                            <span className="bg-rose-500/10 border border-rose-500/20 text-rose-400 px-1 rounded font-bold">EXPLOIT</span>
                          ) : (
                            <span className="bg-amber-500/10 border border-amber-500/20 text-amber-400 px-1 rounded font-bold">THOUGHT</span>
                          )}
                        </span>
                        <span>{e.time}</span>
                      </div>
                      <p className="whitespace-pre-wrap">{cleanMsg}</p>
                    </div>
                  )
                })
            )}
          </div>
        </div>

        {/* CENTER COLUMN: Spectator Live Browser Panel */}
        <div className="flex-1 p-6 flex flex-col h-full bg-zinc-950 overflow-hidden">
          
          {/* Mock Browser Header */}
          <div className="flex-1 flex flex-col border border-zinc-850 rounded-xl overflow-hidden bg-zinc-900/10 shadow-2xl relative">
            
            {/* Browser Nav Controls */}
            <div className="bg-zinc-900/90 border-b border-zinc-850 px-4 py-3 flex items-center space-x-3 shrink-0">
              <div className="flex space-x-1.5 shrink-0">
                <span className="w-3 h-3 rounded-full bg-rose-500/80" />
                <span className="w-3 h-3 rounded-full bg-amber-500/80" />
                <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
              </div>
              
              <div className="flex items-center space-x-2 text-zinc-500 text-xs">
                <ArrowLeft className="w-3.5 h-3.5" />
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
              
              <div className="w-full bg-zinc-950 border border-zinc-850/60 rounded-lg px-3 py-1.5 text-xs text-zinc-400 font-mono truncate select-all">
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
                  <div className="absolute top-4 right-4 bg-zinc-950/80 border border-zinc-800 text-[9px] font-mono text-zinc-400 px-2 py-1 rounded shadow-lg backdrop-blur-sm">
                    Frame loaded: {currentFrame.time}
                  </div>
                </div>
              ) : (
                <div className="text-center space-y-4 flex flex-col items-center">
                  <div className="w-8 h-8 border-2 border-amber-500/30 border-t-amber-500 rounded-full animate-spin" />
                  <span className="text-xs font-mono text-zinc-650">Awaiting Browser Session Stream...</span>
                </div>
              )}
            </div>

            {/* TIMELINE SCRUBBER CONTROLS */}
            {browserHistory.length > 0 && (
              <div className="bg-zinc-900/70 border-t border-zinc-850 px-6 py-4 flex flex-col space-y-3 shrink-0">
                <div className="flex items-center justify-between text-[10px] font-mono text-zinc-400">
                  <div className="flex items-center space-x-2">
                    <Tv className="w-3.5 h-3.5 text-amber-500" />
                    <span>TIMELINE CONTROLLER</span>
                  </div>
                  <span>Frame {historyIndex + 1} / {browserHistory.length}</span>
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
                    <span className="truncate">Active step: {currentFrame.action}</span>
                    <span className="text-zinc-600 shrink-0 pl-4">{currentFrame.time}</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* RIGHT COLUMN: Verdict findings and evidence inspector */}
        <div className="w-96 border-l border-zinc-900 bg-zinc-950/20 p-5 flex flex-col h-full shrink-0">
          
          {/* Right Panel Sub-tab Headers */}
          <div className="flex border-b border-zinc-900 shrink-0">
            <button
              onClick={() => setRightPanelTab('findings')}
              className={`flex-1 py-2 font-mono text-xs font-bold tracking-wider uppercase border-b-2 transition cursor-pointer ${
                rightPanelTab === 'findings' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Live Exploits ({liveVerifiedFindings.length})
            </button>
            <button
              onClick={() => setRightPanelTab('evidence')}
              className={`flex-1 py-2 font-mono text-xs font-bold tracking-wider uppercase border-b-2 transition cursor-pointer ${
                rightPanelTab === 'evidence' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Evidence Feed ({verifications.length})
            </button>
            <button
              onClick={() => setRightPanelTab('report')}
              className={`flex-1 py-2 font-mono text-xs font-bold tracking-wider uppercase border-b-2 transition cursor-pointer ${
                rightPanelTab === 'report' 
                  ? 'border-amber-500 text-amber-500 font-bold' 
                  : 'border-transparent text-zinc-500 hover:text-zinc-300'
              }`}
            >
              Report
            </button>
          </div>

          <div className="flex-1 overflow-y-auto custom-scrollbar pt-4 space-y-4">
            
            {/* FINDINGS SUB-TAB */}
            {rightPanelTab === 'findings' && (
              liveVerifiedFindings.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-650 h-full">
                  <Shield className="w-10 h-10 mb-3 text-zinc-800" />
                  <p className="font-mono text-xs">No verified exploits generated yet.</p>
                </div>
              ) : (
                liveVerifiedFindings.map(f => (
                  <div 
                    key={f.id} 
                    className="border border-zinc-850 bg-zinc-900/10 rounded-xl p-5 relative overflow-hidden shadow-lg leading-relaxed border-l-4 border-l-rose-500"
                  >
                    <div className="flex items-center justify-between mb-2">
                      <span className="px-2 py-0.5 rounded border text-[9px] font-bold font-mono tracking-wider bg-rose-500/10 border-rose-500/20 text-rose-400 uppercase">
                        🟢 Verified Exploit
                      </span>
                      <span className="text-[10px] text-zinc-500 font-mono">{f.severity}</span>
                    </div>
                    
                    <h4 className="text-xs font-bold text-zinc-150 leading-relaxed font-sans">{f.title}</h4>
                    <p className="text-[10px] text-zinc-500 font-mono mt-1 break-all">{f.endpoint}</p>
                    
                    {f.payload && (
                      <div className="mt-3 bg-zinc-950 p-2.5 rounded border border-zinc-900 font-mono text-[9px] text-amber-500/90 break-all select-all">
                        Payload: {f.payload}
                      </div>
                    )}
                  </div>
                ))
              )
            )}

            {/* EVIDENCE SUB-TAB */}
            {rightPanelTab === 'evidence' && (
              verifications.length === 0 ? (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-650 h-full">
                  <FileText className="w-10 h-10 mb-3 text-zinc-800" />
                  <p className="font-mono text-xs">No verification events captured yet.</p>
                </div>
              ) : (
                verifications.map(v => {
                  const isExpanded = expandedVerificationId === v.id
                  const artifacts = parseArtifacts(v.artifacts_json)
                  
                  return (
                    <div 
                      key={v.id} 
                      className="border border-zinc-850 bg-zinc-900/10 hover:border-zinc-800 rounded-xl p-4 transition duration-200"
                    >
                      <div 
                        onClick={() => setExpandedVerificationId(isExpanded ? null : v.id)}
                        className="flex items-start justify-between cursor-pointer"
                      >
                        <div className="space-y-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-[10px] bg-sky-500/10 border border-sky-500/20 text-sky-400 px-1.5 py-0.5 rounded font-mono font-bold uppercase">
                              {v.method}
                            </span>
                            <span className="text-[9px] text-zinc-500 font-mono">Conf: {Math.round(v.confidence * 100)}%</span>
                          </div>
                          <h5 className="font-bold text-zinc-200 text-xs leading-snug">{v.summary}</h5>
                          <p className="text-[9px] text-zinc-500 font-mono truncate max-w-[280px]">{v.endpoint_url}</p>
                        </div>
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-zinc-600" /> : <ChevronRight className="w-4 h-4 text-zinc-600" />}
                      </div>

                      {/* Expanded verification raw traffic inspectors */}
                      {isExpanded && (
                        <div className="mt-4 pt-3 border-t border-zinc-900 font-mono text-[9px] leading-relaxed space-y-3">
                          {v.payload && (
                            <div>
                              <span className="text-zinc-500 block uppercase font-bold tracking-wider mb-1">Payload Applied:</span>
                              <pre className="text-amber-500 bg-zinc-950 p-2 rounded border border-zinc-900 break-all overflow-x-auto whitespace-pre-wrap">{v.payload}</pre>
                            </div>
                          )}

                          {artifacts.map((art: any, aIdx: number) => {
                            if (art.artifact_type === 'request' || art.artifact_type === 'response') {
                              return (
                                <div key={aIdx}>
                                  <span className="text-zinc-500 block uppercase font-bold tracking-wider mb-1">{art.label || art.artifact_type}:</span>
                                  <pre className="text-zinc-400 bg-zinc-950 p-2.5 rounded border border-zinc-900 overflow-x-auto whitespace-pre-wrap max-h-48 break-all custom-scrollbar">
                                    {art.content}
                                  </pre>
                                </div>
                              )
                            }
                            return null
                          })}
                        </div>
                      )}
                    </div>
                  )
                })
              )
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
                      <ArrowUpRight className="w-3 h-3" />
                    </a>
                  </div>
                  <iframe 
                    src={reportUrl} 
                    className="flex-1 w-full bg-white rounded-lg border border-zinc-800 min-h-[500px]"
                    title="Scan Report"
                  />
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center p-8 text-center text-zinc-650 h-full">
                  <FileText className="w-10 h-10 mb-3 text-zinc-800" />
                  <p className="font-mono text-xs">Report will be available after scan completion.</p>
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
            <span>SYSTEM CONSOLE LOGS</span>
          </div>
          {isTerminalExpanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
        </div>

        {/* Console Text Window */}
        {isTerminalExpanded && (
          <div className="h-44 overflow-y-auto bg-black/60 p-5 font-mono text-[10px] text-zinc-400 space-y-1.5 custom-scrollbar border-t border-zinc-900">
            {events.map((e, idx) => (
              <div key={idx} className="flex items-start space-x-3 text-zinc-500">
                <span className="shrink-0 text-zinc-650">{e.time}</span>
                <span className="shrink-0 text-zinc-600 bg-zinc-900/40 px-1 rounded">[{e.type.toUpperCase()}]</span>
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
