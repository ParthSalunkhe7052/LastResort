import React, { useState } from 'react'
import { ShieldAlert, RefreshCw, LayoutDashboard, Sliders, Menu, X } from 'lucide-react'

interface MainLayoutProps {
  children: React.ReactNode
  activeTab: string
  setActiveTab: (tab: any) => void
  goDaemonStatus: string
  pythonAiStatus: string
  targetUrl: string
  onSync: () => void
  currentObjective?: string
  scanStatus?: string
}

export default function MainLayout({
  children,
  activeTab,
  setActiveTab,
  goDaemonStatus,
  pythonAiStatus,
  targetUrl,
  onSync,
  currentObjective = "Initializing...",
  scanStatus = "Idle"
}: MainLayoutProps) {
  const [isSidebarOpen, setIsSidebarOpen] = useState(false)

  return (
    <div className="flex h-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans flex-col">
      
      {/* COCKPIT HEADER */}
      <header className="h-16 border-b border-zinc-850 flex items-center justify-between px-6 bg-zinc-900/40 shrink-0">
        
        {/* Left Section: Hamburger & Branding */}
        <div className="flex items-center space-x-4">
          <button
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="p-1.5 hover:bg-zinc-800 rounded-lg text-zinc-400 hover:text-zinc-200 transition cursor-pointer"
            title="Toggle Menu"
          >
            {isSidebarOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
          
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-5 h-5 text-amber-500 animate-pulse" />
            <div>
              <h1 className="font-bold text-sm tracking-widest text-zinc-50 font-mono">LASTRESORT</h1>
            </div>
          </div>

          {/* System Status Indicators (Subtle dots) */}
          <div className="flex items-center space-x-3 text-[10px] bg-zinc-900/50 px-2.5 py-1 rounded-md border border-zinc-800/80">
            <div className="flex items-center space-x-1.5" title={`Go Core: ${goDaemonStatus}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                goDaemonStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-rose-500'
              }`} />
              <span className="font-mono text-zinc-500">Go</span>
            </div>
            
            <div className="flex items-center space-x-1.5 border-l border-zinc-800 pl-3" title={`AI Engine: ${pythonAiStatus}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${
                pythonAiStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_6px_#10b981]' : 'bg-rose-500'
              }`} />
              <span className="font-mono text-zinc-500">AI</span>
            </div>
          </div>
        </div>

        {/* Center Section: simplified Target, Objective and Scan Status */}
        <div className="flex items-center space-x-6 text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="text-zinc-500">Target:</span>
            <span className="text-amber-500 bg-amber-500/10 px-2.5 py-0.5 rounded border border-amber-500/20 truncate max-w-xs font-bold">
              {targetUrl || 'None'}
            </span>
          </div>

          <div className="flex items-center space-x-2 border-l border-zinc-800 pl-6">
            <span className="text-zinc-500">Objective:</span>
            <span className="text-zinc-200 bg-zinc-800/60 px-2.5 py-0.5 rounded border border-zinc-700/50 truncate max-w-sm font-semibold">
              {currentObjective}
            </span>
          </div>

          <div className="flex items-center space-x-2 border-l border-zinc-800 pl-6">
            <span className="text-zinc-500">Status:</span>
            <span className={`px-2.5 py-0.5 rounded border text-[10px] font-bold ${
              scanStatus === 'RUNNING' ? 'bg-amber-500/10 border-amber-500/30 text-amber-400 animate-pulse' :
              scanStatus === 'COMPLETED' ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' :
              'bg-zinc-850 border-zinc-700 text-zinc-400'
            }`}>
              {scanStatus}
            </span>
          </div>
        </div>

        {/* Right Section: Sync Controls */}
        <div className="flex items-center">
          <button 
            onClick={onSync}
            className="flex items-center space-x-1.5 px-3 py-1.5 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 hover:border-zinc-700 transition rounded-lg text-xs font-mono text-zinc-400 hover:text-zinc-200 cursor-pointer"
          >
            <RefreshCw className="w-3 h-3" />
            <span>Sync</span>
          </button>
        </div>
      </header>

      {/* WORKSPACE CONTAINER */}
      <div className="flex flex-1 overflow-hidden relative">
        
        {/* SIDEBAR (Collapsible drawer overlay or inline) */}
        <aside className={`absolute md:relative top-0 bottom-0 left-0 z-40 w-64 border-r border-zinc-900 bg-zinc-950 md:bg-zinc-900/10 p-6 flex flex-col justify-between shrink-0 transition-transform duration-350 ease-in-out ${
          isSidebarOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0 md:hidden'
        }`}>
          <nav className="space-y-2">
            <button
              onClick={() => {
                setActiveTab('dashboard');
                setIsSidebarOpen(false);
              }}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-xs font-mono tracking-wider transition-all duration-200 cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20 font-bold'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border border-transparent'
              }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>DASHBOARD</span>
            </button>
            
            <button
              onClick={() => {
                setActiveTab('settings');
                setIsSidebarOpen(false);
              }}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-xs font-mono tracking-wider transition-all duration-200 cursor-pointer ${
                activeTab === 'settings'
                  ? 'bg-amber-500/10 text-amber-500 border border-amber-500/20 font-bold'
                  : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40 border border-transparent'
              }`}
            >
              <Sliders className="w-4 h-4" />
              <span>AI & SETTINGS</span>
            </button>
          </nav>
          
          <div className="border-t border-zinc-900 pt-6 text-[10px] text-zinc-500 font-mono space-y-1">
            <div>LastResort Rig Console v0.1.0</div>
            <div>Spectator Portal Active</div>
          </div>
        </aside>

        {/* Overlay backdrop for mobile view when sidebar is open */}
        {isSidebarOpen && (
          <div 
            onClick={() => setIsSidebarOpen(false)}
            className="md:hidden absolute inset-0 bg-black/60 z-30 transition-opacity"
          />
        )}

        {/* MAIN WORKSPACE CONTENT */}
        <main className="flex-1 overflow-hidden bg-zinc-950 flex flex-col relative">
          {children}
        </main>
      </div>

    </div>
  )
}
