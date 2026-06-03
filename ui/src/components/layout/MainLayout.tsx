import React from 'react'
import { ShieldAlert, RefreshCw } from 'lucide-react'

interface MainLayoutProps {
  children: React.ReactNode
  activeTab: string
  setActiveTab: (tab: any) => void
  goDaemonStatus: string
  pythonAiStatus: string
  targetUrl: string
  onSync: () => void
}

export default function MainLayout({
  children,
  goDaemonStatus,
  pythonAiStatus,
  targetUrl,
  onSync
}: MainLayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans flex-col">
      
      {/* COCKPIT HEADER */}
      <header className="h-20 border-b border-zinc-800 flex items-center justify-between px-8 bg-zinc-900/40 shrink-0">
        <div className="flex items-center space-x-3">
          <ShieldAlert className="w-8 h-8 text-amber-500 animate-pulse" />
          <div>
            <h1 className="font-bold text-lg tracking-wider text-zinc-50">LASTRESORT</h1>
            <p className="text-[10px] text-zinc-500 font-mono">Hacker Simulation Console v0.1.0-alpha</p>
          </div>
        </div>

        <div className="flex items-center space-x-8">
          <div className="flex items-center space-x-6 text-xs bg-zinc-950/60 px-4 py-2 rounded-lg border border-zinc-800">
            <div className="flex items-center space-x-2">
              <span className="text-zinc-500 font-mono">Go Core:</span>
              <span className={`w-2 h-2 rounded-full ${
                goDaemonStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 'bg-rose-500'
              }`} />
              <span className="font-mono text-zinc-400 capitalize">{goDaemonStatus}</span>
            </div>
            
            <div className="flex items-center space-x-2 border-l border-zinc-800 pl-6">
              <span className="text-zinc-500 font-mono">AI Engine:</span>
              <span className={`w-2 h-2 rounded-full ${
                pythonAiStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 'bg-rose-500'
              }`} />
              <span className="font-mono text-zinc-400 capitalize">{pythonAiStatus}</span>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            <span className="text-xs text-zinc-500 font-mono">Target:</span>
            <span className="text-xs font-mono text-amber-500 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/20">
              {targetUrl || 'None'}
            </span>
          </div>

          <button 
            onClick={onSync}
            className="flex items-center space-x-2 px-4 py-2 bg-zinc-850 hover:bg-zinc-800 border border-zinc-700 transition rounded-lg text-xs font-mono text-zinc-300 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Sync</span>
          </button>
        </div>
      </header>

      {/* WORKSPACE AREA */}
      <main className="flex-1 overflow-hidden p-8 flex flex-col bg-zinc-950">
        {children}
      </main>

    </div>
  )
}
