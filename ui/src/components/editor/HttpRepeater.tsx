import { Send } from 'lucide-react'

interface HttpRepeaterProps {
  repeaterHost: string
  setRepeaterHost: (host: string) => void
  repeaterTls: boolean
  setRepeaterTls: (tls: boolean) => void
  repeaterRequest: string
  setRepeaterRequest: (req: string) => void
  repeaterResponse: string
  isSendingRepeater: boolean
  handleSendRepeater: () => void
}

export default function HttpRepeater({
  repeaterHost,
  setRepeaterHost,
  repeaterTls,
  setRepeaterTls,
  repeaterRequest,
  setRepeaterRequest,
  repeaterResponse,
  isSendingRepeater,
  handleSendRepeater
}: HttpRepeaterProps) {
  return (
    <div className="flex-1 flex gap-6 overflow-hidden">
      {/* Left pane: request crafting */}
      <div className="flex-1 flex flex-col border border-zinc-800 bg-zinc-900/10 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800 flex flex-wrap items-center gap-6 bg-zinc-900/40 shrink-0">
          <div className="flex items-center space-x-2">
            <label className="text-[10px] font-mono text-zinc-500">TARGET HOST</label>
            <input 
              type="text" 
              value={repeaterHost}
              onChange={e => setRepeaterHost(e.target.value)}
              className="bg-zinc-950 border border-zinc-800 text-xs font-mono text-zinc-300 rounded px-2.5 py-1 focus:outline-none focus:border-emerald-500 w-48"
              placeholder="example.com"
            />
          </div>

          <label className="flex items-center space-x-2 bg-zinc-950 border border-zinc-800 rounded px-2 py-1 text-[10px] font-mono text-zinc-400 select-none cursor-pointer">
            <input 
              type="checkbox" 
              checked={repeaterTls} 
              onChange={() => setRepeaterTls(!repeaterTls)}
              className="accent-emerald-500 rounded bg-zinc-900 border-zinc-850" 
            />
            <span>Use HTTPS (SSL/TLS)</span>
          </label>

          <button 
            onClick={handleSendRepeater}
            disabled={isSendingRepeater}
            className="bg-emerald-500 hover:bg-emerald-600 disabled:bg-zinc-800 disabled:text-zinc-600 text-zinc-950 font-mono text-xs px-4 py-1.5 rounded font-bold shadow-[0_0_10px_rgba(16,185,129,0.1)] border border-emerald-400 flex items-center space-x-1.5 cursor-pointer"
          >
            <Send className="w-3.5 h-3.5 fill-zinc-950" />
            <span>{isSendingRepeater ? 'Sending...' : 'Send Request'}</span>
          </button>
        </div>

        <div className="flex-1 p-6 flex flex-col overflow-hidden">
          <span className="block text-[10px] font-mono text-zinc-400 mb-2">RAW REQUEST SPECIFICATION</span>
          <textarea 
            value={repeaterRequest}
            onChange={e => setRepeaterRequest(e.target.value)}
            className="flex-1 w-full bg-zinc-950 border border-zinc-800 text-zinc-300 font-mono text-xs rounded-xl p-4 focus:outline-none focus:border-zinc-700 resize-none leading-relaxed"
          />
        </div>
      </div>

      {/* Right pane: response viewer */}
      <div className="flex-1 flex flex-col border border-zinc-800 bg-zinc-950 rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800 bg-zinc-900/40 shrink-0">
          <span className="text-xs font-mono text-zinc-200">Raw Server Response</span>
        </div>
        <div className="flex-1 p-6 overflow-y-auto font-mono text-xs text-zinc-400 bg-zinc-950 leading-relaxed whitespace-pre-wrap select-text">
          {repeaterResponse ? (
            <code className="text-zinc-300">{repeaterResponse}</code>
          ) : (
            <span className="text-zinc-600 italic block text-center mt-32">Click Send Request to dispatch and display the raw response bytes.</span>
          )}
        </div>
      </div>
    </div>
  )
}
