import React, { useState, useEffect, useRef } from 'react'
import { Terminal, ChevronDown, ChevronRight } from 'lucide-react'
import ScanLaunchForm from './ScanLaunchForm'
import LiveBrowserPanel from './LiveBrowserPanel'
import EventTimeline from './EventTimeline'
import ManualGuidePanel from './ManualGuidePanel'
import ModuleStatusPanel from './ModuleStatusPanel'
import ReportPanel from './ReportPanel'
import AIPipelinePanel from './AIPipelinePanel'
import ToolStatusPanel from './ToolStatusPanel'
import FindingsSummary from './FindingsSummary'

interface ScanEventRecord {
  time: string
  type: string
  message: string
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
  authCookie: string
  setAuthCookie: (cookie: string) => void
  scopePatternsText: string
  setScopePatternsText: (text: string) => void
  scanProfile: number
  setScanProfile: (profile: number) => void
  goDaemonStatus: string
  isStartingScan: boolean
  handleStartScan: (e: React.FormEvent, testingMode: number) => void
  events: ScanEventRecord[]
  scanModules: any[]
  activeScanId: string | null
  liveScreenshot: string | null
  performanceMetrics: any
  verifications?: StoredVerification[]
  reportUrl?: string | null
  manualGuide?: string | null
  testingMode?: number
  }

  export default function Dashboard({
  targetUrl,
  setTargetUrl,
  authCookie,
  setAuthCookie,
  scopePatternsText,
  setScopePatternsText,
  scanProfile,
  setScanProfile,
  goDaemonStatus,
  isStartingScan,
  handleStartScan,
  events,
  scanModules,
  activeScanId,
  liveScreenshot,
  performanceMetrics,
  verifications = [],
  reportUrl = null,
  manualGuide = null,
  testingMode = 1
  }: DashboardProps) {
  // Timeline Scrubber States
  const [browserHistory, setBrowserHistory] = useState<{ screenshot: string; time: string; action: string }[]>([])
  const [historyIndex, setHistoryIndex] = useState<number>(-1)

  // Collapsible terminal section
  const [isTerminalExpanded, setIsTerminalExpanded] = useState(false)
  
  // Right panel sub-tab
  const [rightPanelTab, setRightPanelTab] = useState<'attacks' | 'verifications' | 'modules' | 'report' | 'guide'>('verifications')

  // Auto-switch to guide tab when it arrives
  useEffect(() => {
    if (manualGuide) {
      setRightPanelTab('guide')
    }
  }, [manualGuide])

  // Refs for auto-scroll
  const thoughtsEndRef = useRef<HTMLDivElement>(null)
  const terminalEndRef = useRef<HTMLDivElement>(null)

  // Add new browser screenshot frames as they stream in
  useEffect(() => {
    if (liveScreenshot) {
      setBrowserHistory(prev => {
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

  // Renders the initial Landing Setup Screen
  if (!activeScanId) {
    return (
      <div className="flex-1 flex flex-col justify-center overflow-y-auto">
        <ScanLaunchForm
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          authCookie={authCookie}
          setAuthCookie={setAuthCookie}
          scopePatternsText={scopePatternsText}
          setScopePatternsText={setScopePatternsText}
          scanProfile={scanProfile}
          setScanProfile={setScanProfile}
          goDaemonStatus={goDaemonStatus}
          isStartingScan={isStartingScan}
          handleStartScan={handleStartScan}
        />
      </div>
    )
  }

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-zinc-950 text-zinc-300">
      
      {/* Simulation Workspace Panel */}
      <div className="flex flex-1 overflow-hidden">
        
        {testingMode === 2 ? (
          <>
            {/* MANUAL MODE: 3-column layout (Tools + Stream + Manual Guide) */}
            
            {/* LEFT: Tool Status Panel */}
            <div className="w-[200px] border-r border-zinc-900 bg-zinc-950/40 p-4 flex flex-col h-full shrink-0 overflow-hidden">
              <ToolStatusPanel scanModules={scanModules} />
              {activeScanId && (
                <div className="mt-6">
                  <FindingsSummary scanId={activeScanId} />
                </div>
              )}
            </div>

            {/* CENTER: Cognitive Agent Activity Feed */}
            <EventTimeline
              events={events}
              thoughtsEndRef={thoughtsEndRef}
            />

            {/* RIGHT: Dedicated Manual Guide Panel */}
            <div className="w-[480px] border-l border-zinc-900 bg-zinc-950/20 p-5 flex flex-col h-full shrink-0 overflow-hidden">
              <div className="flex items-center border-b border-zinc-900 shrink-0 pb-3 mb-4">
                <span className="text-[10px] font-mono font-bold tracking-wider uppercase text-amber-500">Manual Testing Guide</span>
              </div>
              <div className="flex-1 overflow-y-auto custom-scrollbar">
                <ManualGuidePanel
                  guide={manualGuide}
                />
              </div>
            </div>
          </>
        ) : (
          <>
            {/* AUTOMATED MODE: 3-column layout (Browser + Stream + Inspector) */}
            
            {/* LEFT COLUMN: Spectator Live Browser Panel */}
            <div className="flex-[1.3] p-5 flex flex-col h-full bg-zinc-950 overflow-hidden border-r border-zinc-900/80">
              <LiveBrowserPanel
                targetUrl={targetUrl}
                browserHistory={browserHistory}
                historyIndex={historyIndex}
                setHistoryIndex={setHistoryIndex}
              />
            </div>
            
            {/* CENTER COLUMN: Cognitive Agent Activity Feed */}
            <EventTimeline
              events={events}
              thoughtsEndRef={thoughtsEndRef}
            />

            {/* RIGHT COLUMN: Verdict findings and evidence inspector */}
            <div className="w-[420px] border-l border-zinc-900 bg-zinc-950/20 p-5 flex flex-col h-full shrink-0 overflow-hidden">
              
              {/* Right Panel Sub-tab Headers */}
              <div className="flex border-b border-zinc-900 shrink-0 text-[10px] font-mono gap-1">
                <button
                  onClick={() => setRightPanelTab('guide')}
                  className={`flex-1 pb-2 font-bold tracking-wider uppercase border-b-2 transition cursor-pointer text-center ${
                    rightPanelTab === 'guide' 
                      ? 'border-amber-500 text-amber-500 font-bold' 
                      : 'border-transparent text-zinc-500 hover:text-zinc-300'
                  }`}
                >
                  Manual Guide
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
                {rightPanelTab === 'guide' && (
                  <ManualGuidePanel
                    guide={manualGuide}
                  />
                )}

                {rightPanelTab === 'verifications' && (
                  <AIPipelinePanel
                    verifications={verifications}
                  />
                )}

                {rightPanelTab === 'modules' && (
                  <ModuleStatusPanel
                    scanModules={scanModules}
                    performanceMetrics={performanceMetrics}
                    verificationsCount={verifications.length}
                  />
                )}

                {rightPanelTab === 'report' && (
                  <ReportPanel
                    reportUrl={reportUrl}
                  />
                )}
              </div>
            </div>
          </>
        )}
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
                if (!e.message) return false
                const msg = e.message.toLowerCase()
                if (msg.includes('failed to load resource: net::err')) return false
                if (msg.includes('browser.screenshot')) return false
                return true
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
