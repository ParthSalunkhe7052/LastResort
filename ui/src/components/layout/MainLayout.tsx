import React from 'react'
import { 
  ShieldAlert, Activity, History, Send, AlertTriangle, Cpu, 
  Settings as SettingsIcon, RefreshCw, Network, Layers
} from 'lucide-react'

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
  activeTab,
  setActiveTab,
  goDaemonStatus,
  pythonAiStatus,
  targetUrl,
  onSync
}: MainLayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-zinc-950 text-zinc-100 font-sans">
      
      {/* SIDEBAR */}
      <div className="w-64 border-r border-zinc-800 bg-zinc-900/50 flex flex-col justify-between shrink-0">
        <div>
          {/* Logo */}
          <div className="p-6 border-b border-zinc-800 flex items-center space-x-3">
            <ShieldAlert className="w-8 h-8 text-amber-500 animate-pulse" />
            <div>
              <h1 className="font-bold text-lg tracking-wider text-zinc-50">LASTRESORT</h1>
              <p className="text-xs text-zinc-500 font-mono">v0.1.0-alpha</p>
            </div>
          </div>

          {/* Navigation */}
          <nav className="p-4 space-y-1">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'dashboard'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <Activity className="w-4 h-4 text-amber-500" />
              <span>Assessment Dashboard</span>
            </button>
            <button
              onClick={() => setActiveTab('endpoints')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'endpoints'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <Network className="w-4 h-4 text-orange-400" />
              <span>Endpoints Map</span>
            </button>
            <button
              onClick={() => setActiveTab('proxy-history')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'proxy-history'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <History className="w-4 h-4 text-sky-400" />
              <span>Proxy History</span>
            </button>
            <button
              onClick={() => setActiveTab('repeater')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'repeater'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <Send className="w-4 h-4 text-emerald-400" />
              <span>HTTP Repeater</span>
            </button>
            <button
              onClick={() => setActiveTab('findings')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'findings'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <AlertTriangle className="w-4 h-4 text-rose-500" />
              <span>Findings Browser</span>
            </button>
            <button
              onClick={() => setActiveTab('reports')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'reports'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <Layers className="w-4 h-4 text-teal-400" />
              <span>Report Generator</span>
            </button>
            <button
              onClick={() => setActiveTab('ai-console')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'ai-console'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <Cpu className="w-4 h-4 text-purple-400" />
              <span>AI Agent Console</span>
            </button>
            <button
              onClick={() => setActiveTab('settings')}
              className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition ${
                activeTab === 'settings'
                  ? 'bg-zinc-800 text-zinc-100 border border-zinc-700'
                  : 'text-zinc-400 hover:bg-zinc-800/40 hover:text-zinc-200'
              }`}
            >
              <SettingsIcon className="w-4 h-4 text-zinc-400" />
              <span>Daemon Settings</span>
            </button>
          </nav>
        </div>

        {/* System Connection Indicators */}
        <div className="p-4 border-t border-zinc-800 space-y-3 bg-zinc-900/30">
          <div className="flex items-center justify-between text-xs">
            <span className="text-zinc-400 font-mono">Go Core Daemon</span>
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${
                goDaemonStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 
                goDaemonStatus === 'connecting' ? 'bg-amber-500 animate-pulse' : 'bg-rose-500'
              }`} />
              <span className="font-medium text-zinc-300 capitalize">{goDaemonStatus}</span>
            </div>
          </div>

          <div className="flex items-center justify-between text-xs">
            <span className="text-zinc-400 font-mono">Python AI IPC</span>
            <div className="flex items-center space-x-2">
              <span className={`w-2.5 h-2.5 rounded-full ${
                pythonAiStatus === 'connected' ? 'bg-emerald-500 shadow-[0_0_8px_#10b981]' : 
                pythonAiStatus === 'connecting' ? 'bg-amber-500 animate-pulse' : 'bg-rose-500'
              }`} />
              <span className="font-medium text-zinc-300 capitalize">{pythonAiStatus}</span>
            </div>
          </div>
        </div>
      </div>

      {/* MAIN CONTAINER */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* HEADER */}
        <header className="h-16 border-b border-zinc-800 flex items-center justify-between px-8 bg-zinc-900/20 shrink-0">
          <div className="flex items-center space-x-4">
            <span className="text-sm text-zinc-400">Target URL:</span>
            <span className="text-sm font-mono text-amber-500 bg-amber-500/10 px-3 py-1 rounded-full border border-amber-500/20">
              {targetUrl || 'None Configured'}
            </span>
          </div>
          <button 
            onClick={onSync}
            className="flex items-center space-x-2 px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 transition rounded-lg text-xs font-mono text-zinc-300 cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Sync System</span>
          </button>
        </header>

        {/* WORKSPACE AREA */}
        <main className="flex-1 overflow-hidden p-8 flex flex-col">
          {children}
        </main>
      </div>

    </div>
  )
}
