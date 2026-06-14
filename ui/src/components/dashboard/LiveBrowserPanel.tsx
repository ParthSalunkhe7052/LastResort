import { Tv, ArrowLeft, ArrowRight } from 'lucide-react'

interface BrowserFrame {
  screenshot: string
  time: string
  action: string
}

interface LiveBrowserPanelProps {
  targetUrl: string
  browserHistory: BrowserFrame[]
  historyIndex: number
  setHistoryIndex: (idx: number) => void
}

export default function LiveBrowserPanel({
  targetUrl,
  browserHistory,
  historyIndex,
  setHistoryIndex
}: LiveBrowserPanelProps) {
  const currentFrame = historyIndex >= 0 && historyIndex < browserHistory.length ? browserHistory[historyIndex] : null

  return (
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
            {/* Realtime Stream Overlay */}
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
            <button
              disabled={historyIndex <= 0}
              onClick={() => setHistoryIndex(historyIndex - 1)}
              className="p-1 bg-zinc-950 border border-zinc-800 rounded hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-zinc-950 transition cursor-pointer text-zinc-400"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>

            <input
              type="range"
              min="0"
              max={browserHistory.length - 1}
              value={historyIndex}
              onChange={e => setHistoryIndex(Number(e.target.value))}
              className="flex-1 accent-amber-500 bg-zinc-950 h-1 rounded-lg cursor-pointer appearance-none border border-zinc-800"
            />

            <button
              disabled={historyIndex >= browserHistory.length - 1}
              onClick={() => setHistoryIndex(historyIndex + 1)}
              className="p-1 bg-zinc-950 border border-zinc-800 rounded hover:bg-zinc-800 disabled:opacity-30 disabled:hover:bg-zinc-950 transition cursor-pointer text-zinc-400"
            >
              <ArrowRight className="w-4 h-4" />
            </button>
          </div>

          {currentFrame && (
            <div className="bg-zinc-950/60 border border-zinc-900 p-2 rounded text-[10px] font-mono text-zinc-400 flex items-center justify-between">
              <span className="truncate text-zinc-400">Action: <strong className="text-zinc-200 font-semibold">{currentFrame.action}</strong></span>
              <span className="text-zinc-650 shrink-0 pl-4">{currentFrame.time}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
