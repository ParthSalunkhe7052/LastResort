import { Play, Layers, Terminal, Database } from 'lucide-react'
import { ScanProfile } from '../../gen/scan/v1/scan_pb'

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
  detectedTechnologies?: string
  authModel?: string
}

interface DashboardProps {
  targetUrl: string
  setTargetUrl: (url: string) => void
  profile: ScanProfile
  setProfile: (profile: ScanProfile) => void
  enabledModules: any
  setEnabledModules: (modules: any) => void
  goDaemonStatus: string
  isStartingScan: boolean
  handleStartScan: (e: React.FormEvent) => void
  events: ScanEventRecord[]
  scans: ScanRecord[]
  setActiveScanId: (id: string) => void
  subscribeToEvents: (id: string) => void
}

export default function Dashboard({
  targetUrl,
  setTargetUrl,
  profile,
  setProfile,
  enabledModules,
  setEnabledModules,
  goDaemonStatus,
  isStartingScan,
  handleStartScan,
  events,
  scans,
  setActiveScanId,
  subscribeToEvents
}: DashboardProps) {
  return (
    <div className="space-y-6 flex-1 overflow-y-auto max-w-6xl pr-2">
      {/* TARGET CONFIG CARD */}
      <div className="border border-zinc-800 bg-zinc-900/30 rounded-xl p-6 shadow-xl backdrop-blur-sm">
        <h3 className="font-semibold text-lg text-zinc-100 flex items-center space-x-2 mb-4">
          <Layers className="w-5 h-5 text-amber-500" />
          <span>Configure Security Assessment</span>
        </h3>
        
        <form onSubmit={handleStartScan} className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-end">
            <div className="md:col-span-2">
              <label className="block text-xs font-mono text-zinc-400 mb-2">TARGET URL (MUST BE AUTHORIZED)</label>
              <input
                type="url"
                required
                value={targetUrl}
                onChange={e => setTargetUrl(e.target.value)}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2.5 text-zinc-100 font-mono focus:outline-none focus:border-amber-500 transition"
                placeholder="http://localhost:8000"
              />
            </div>

            <div>
              <label className="block text-xs font-mono text-zinc-400 mb-2">SCAN PROFILE</label>
              <select
                value={profile}
                onChange={e => setProfile(Number(e.target.value))}
                className="w-full bg-zinc-950 border border-zinc-800 rounded-lg px-4 py-2.5 text-zinc-100 font-mono focus:outline-none focus:border-amber-500 transition"
              >
                <option value={ScanProfile.QUICK}>Quick Profile (Recon only)</option>
                <option value={ScanProfile.STANDARD}>Standard Profile (Active scanning)</option>
                <option value={ScanProfile.DEEP}>Deep Profile (Full AI Planning)</option>
              </select>
            </div>
          </div>

          {/* Modules selection */}
          <div className="border-t border-zinc-800/80 pt-4">
            <label className="block text-xs font-mono text-zinc-400 mb-3">ENABLED TESTING MODULES</label>
            <div className="flex flex-wrap gap-4">
              {Object.entries(enabledModules).map(([moduleKey, isEnabled]) => (
                <label key={moduleKey} className="flex items-center space-x-2.5 bg-zinc-950/60 border border-zinc-800 rounded-lg px-3 py-2 text-xs font-mono text-zinc-300 hover:border-zinc-700 cursor-pointer select-none">
                  <input 
                    type="checkbox" 
                    checked={isEnabled as boolean} 
                    onChange={() => setEnabledModules((prev: any) => ({ ...prev, [moduleKey]: !isEnabled }))}
                    className="rounded accent-amber-500 bg-zinc-900 border-zinc-800 text-zinc-950" 
                  />
                  <span className="capitalize">{moduleKey.replace(/([A-Z])/g, ' $1')}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="flex justify-end pt-2">
            <button
              type="submit"
              disabled={goDaemonStatus !== 'connected' || isStartingScan}
              className="flex items-center space-x-2 bg-amber-500 hover:bg-amber-600 disabled:bg-zinc-800 disabled:text-zinc-600 disabled:border-transparent text-zinc-950 px-6 py-3 rounded-lg font-semibold transition tracking-wide cursor-pointer disabled:cursor-not-allowed shadow-[0_0_20px_rgba(245,158,11,0.2)] border border-amber-400"
            >
              <Play className="w-4 h-4 fill-zinc-950" />
              <span>{isStartingScan ? 'Initializing Orchestrator...' : 'Start Assessment'}</span>
            </button>
          </div>
        </form>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* SYSTEM STREAM TERMINAL */}
        <div className="border border-zinc-800 bg-zinc-950 rounded-xl flex flex-col h-[400px]">
          <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-800 bg-zinc-900/40">
            <h3 className="font-semibold text-sm flex items-center space-x-2 text-zinc-100">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span className="font-mono">Orchestration Event Logs</span>
            </h3>
          </div>
          
          <div className="flex-1 p-6 overflow-y-auto font-mono text-xs space-y-2.5 flex flex-col-reverse">
            {events.length === 0 ? (
              <span className="text-zinc-600 italic">No events streamed yet. Trigger a scan above to start the IPC loop.</span>
            ) : (
              events.map((e, index) => (
                <div key={index} className={`flex space-x-3 leading-relaxed border-l-2 pl-3 ${
                  e.type === 'error' ? 'text-rose-400 border-rose-500' :
                  e.type === 'finding.new' ? 'text-amber-300 border-amber-500 bg-amber-500/5 py-1' :
                  e.type === 'hypothesis.generated' ? 'text-violet-300 border-violet-500 bg-violet-500/5 py-1' :
                  e.type === 'phase.started' || e.type === 'phase.completed' ? 'text-cyan-400 border-cyan-500 font-bold' :
                  e.type === 'log.error' ? 'text-rose-400 border-rose-500' :
                  e.type === 'log.warning' ? 'text-yellow-300 border-yellow-500' :
                  'text-zinc-400 border-zinc-800'
                }`}>
                  <span className="text-zinc-600 shrink-0">{e.time}</span>
                  <span>{e.message}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* HISTORICAL SCANS */}
        <div className="border border-zinc-800 bg-zinc-900/30 rounded-xl flex flex-col h-[400px] backdrop-blur-sm">
          <div className="px-6 py-4 border-b border-zinc-800">
            <h3 className="font-semibold text-sm flex items-center space-x-2 text-zinc-100">
              <Database className="w-4 h-4 text-amber-500" />
              <span>SQLite Database History</span>
            </h3>
          </div>

          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {scans.length === 0 ? (
              <span className="text-zinc-500 text-xs italic block">No historical scans stored in database.</span>
            ) : (
              scans.map((s, idx) => (
                <div 
                  key={idx} 
                  onClick={() => {
                    setActiveScanId(s.id);
                    subscribeToEvents(s.id);
                  }}
                  className={`p-4 border rounded-xl bg-zinc-950/60 hover:bg-zinc-900/60 transition cursor-pointer flex flex-col justify-between space-y-2 border-zinc-800`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-amber-500 truncate max-w-[250px]">{s.targetUrl}</span>
                    <span className={`text-[10px] px-2.5 py-0.5 rounded-full border uppercase ${
                      s.status === 'SCAN_STATUS_COMPLETED' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' :
                      s.status === 'SCAN_STATUS_RUNNING' ? 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400' :
                      'bg-zinc-800 border-zinc-700 text-zinc-400'
                    }`}>{s.status.replace('SCAN_STATUS_', '')}</span>
                  </div>
                  
                  <div className="flex items-center justify-between text-[11px] text-zinc-400">
                    <span>ID: <span className="font-mono">{s.id.slice(0, 8)}...</span></span>
                    <span>Profile: <span className="font-mono text-zinc-300">{s.profile.replace('SCAN_PROFILE_', '')}</span></span>
                  </div>

                  {s.detectedTechnologies && (
                    <div className="text-[10px] text-zinc-400 font-mono bg-zinc-900/60 p-2.5 rounded border border-zinc-800/80 space-y-1 mt-1">
                      <div><span className="text-zinc-500 font-semibold">Tech:</span> <span className="text-amber-500/90">{s.detectedTechnologies}</span></div>
                      {s.authModel && <div><span className="text-zinc-500 font-semibold">Auth:</span> <span className="text-cyan-400/90">{s.authModel}</span></div>}
                    </div>
                  )}

                  <div className="w-full bg-zinc-800 rounded-full h-1.5 mt-1">
                    <div className="bg-amber-500 h-1.5 rounded-full" style={{ width: `${s.progress * 100}%` }}></div>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
