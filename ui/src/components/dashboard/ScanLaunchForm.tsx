import { Cpu, Play } from 'lucide-react'

interface ScanLaunchFormProps {
  targetUrl: string
  setTargetUrl: (url: string) => void
  authCookie: string
  setAuthCookie: (cookie: string) => void
  scopePatternsText: string
  setScopePatternsText: (text: string) => void
  scanProfile: number // 1: Quick, 2: Standard, 3: Deep
  setScanProfile: (profile: number) => void
  goDaemonStatus: string
  isStartingScan: boolean
  handleStartScan: (e: React.FormEvent, testingMode: number) => void
}

export default function ScanLaunchForm({
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
  handleStartScan
}: ScanLaunchFormProps) {
  return (
    <div className="flex flex-col items-center justify-center flex-1 max-w-xl mx-auto space-y-8 py-16 px-4">
      <div className="text-center space-y-3">
        <div className="inline-flex p-4 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-500 animate-pulse animate-duration-3000">
          <Cpu className="w-8 h-8" />
        </div>
        <h2 className="text-2xl font-extrabold tracking-widest font-mono text-zinc-100 uppercase">LastResort Rig</h2>
        <p className="text-xs text-zinc-500 font-mono">Autonomous state-aware browser pentester</p>
      </div>

      <div className="w-full bg-zinc-900/30 border border-zinc-850 rounded-xl p-8 space-y-6 backdrop-blur-md shadow-2xl">
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

          <div>
            <label className="block text-[10px] font-mono text-zinc-500 mb-1.5 uppercase tracking-wider">Scope Patterns (Optional, One Per Line)</label>
            <textarea
              value={scopePatternsText}
              onChange={e => setScopePatternsText(e.target.value)}
              className="w-full bg-zinc-950 border border-zinc-850 rounded-lg px-4 py-2 text-zinc-100 font-mono text-xs focus:outline-none focus:border-amber-500 transition min-h-[60px]"
              placeholder="example.com/api/.*\nexample.com/dashboard/.*"
            />
          </div>

          <div>
            <label className="block text-[10px] font-mono text-zinc-500 mb-1.5 uppercase tracking-wider">Crawl/Attack Profile</label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { val: 1, label: 'Quick', desc: 'Passive only' },
                { val: 2, label: 'Standard', desc: 'Passive + Fuzz' },
                { val: 3, label: 'Deep', desc: 'AI agent loops' }
              ].map(p => (
                <button
                  key={p.val}
                  type="button"
                  onClick={() => setScanProfile(p.val)}
                  className={`p-2.5 rounded-lg border text-left font-mono transition cursor-pointer flex flex-col justify-between ${
                    scanProfile === p.val
                      ? 'border-amber-500 bg-amber-500/10 text-amber-400'
                      : 'border-zinc-850 bg-zinc-950 hover:bg-zinc-900 text-zinc-400'
                  }`}
                >
                  <span className="text-xs font-bold">{p.label}</span>
                  <span className="text-[8px] text-zinc-500 font-mono">{p.desc}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 pt-2">
            <button
              type="button"
              onClick={(e) => handleStartScan(e, 1)}
              disabled={goDaemonStatus !== 'connected' || isStartingScan}
              className="flex items-center justify-center space-x-2 bg-amber-500 hover:bg-amber-600 disabled:bg-zinc-850 disabled:text-zinc-600 disabled:border-transparent text-zinc-950 py-3.5 rounded-lg font-semibold transition tracking-wide cursor-pointer disabled:cursor-not-allowed border border-amber-400 font-mono text-xs shadow-[0_0_20px_rgba(245,158,11,0.15)]"
            >
              <Play className="w-3.5 h-3.5 fill-zinc-950" />
              <span className="uppercase">{isStartingScan ? '...' : 'Automated Pentest'}</span>
            </button>
            <button
              type="button"
              onClick={(e) => handleStartScan(e, 2)}
              disabled={goDaemonStatus !== 'connected' || isStartingScan}
              className="flex items-center justify-center space-x-2 bg-zinc-100 hover:bg-zinc-200 disabled:bg-zinc-850 disabled:text-zinc-600 disabled:border-transparent text-zinc-950 py-3.5 rounded-lg font-semibold transition tracking-wide cursor-pointer disabled:cursor-not-allowed border border-zinc-300 font-mono text-xs"
            >
              <Cpu className="w-3.5 h-3.5" />
              <span className="uppercase">{isStartingScan ? '...' : 'Manual Review'}</span>
            </button>
          </div>
        </div>

        <div className="border-t border-zinc-850 pt-4 flex items-center justify-between text-[10px] text-zinc-500 font-mono">
          <span>Daemon connection: <span className="text-emerald-500 font-bold uppercase">{goDaemonStatus}</span></span>
          <span>Real-time spectator engine ready</span>
        </div>
      </div>
    </div>
  )
}
