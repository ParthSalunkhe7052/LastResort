
import { Settings as SettingsIcon } from 'lucide-react'

export default function Settings() {
  return (
    <div className="max-w-xl border border-zinc-800 bg-zinc-900/30 rounded-xl p-8 space-y-6">
      <h3 className="font-semibold text-lg flex items-center space-x-2 text-zinc-100">
        <SettingsIcon className="w-6 h-6 text-amber-500" />
        <span>System Configuration Settings</span>
      </h3>
      <div className="space-y-4">
        <div>
          <label className="block text-xs font-mono text-zinc-400 mb-2">GEMINI API KEY</label>
          <input
            type="password"
            disabled
            value="••••••••••••••••••••••••••••••••••••••••"
            className="w-full bg-zinc-950 border border-zinc-800 text-zinc-500 font-mono rounded-lg px-4 py-2.5"
          />
          <span className="text-[10px] text-zinc-500 mt-2 block">Key loaded from local workspace .env file</span>
        </div>

        <div>
          <label className="block text-xs font-mono text-zinc-400 mb-2">LOCAL CERTIFICATE STORAGE</label>
          <input
            type="text"
            disabled
            value="./data/certs"
            className="w-full bg-zinc-950 border border-zinc-800 text-zinc-500 font-mono rounded-lg px-4 py-2.5"
          />
        </div>
      </div>
    </div>
  )
}
