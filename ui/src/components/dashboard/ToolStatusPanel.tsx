import { useState, useEffect } from 'react'
import { Wrench, Check, X, Loader2 } from 'lucide-react'
import { BASE_URL } from '../../api/client'

interface ToolStatus {
  name: string
  available: boolean
  install_cmd: string
  description: string
}

interface ToolStatusPanelProps {
  scanModules?: any[]
}

const TOOL_ORDER = ['nuclei', 'httpx', 'wapiti', 'dalfox', 'corsy', 'nikto', 'sslyze']

const TOOL_ICONS: Record<string, string> = {
  nuclei: '🔍',
  httpx: '🌐',
  wapiti: '🕷️',
  dalfox: '💉',
  corsy: '🔗',
  nikto: '🖥️',
  sslyze: '🔒',
}

export default function ToolStatusPanel({ scanModules = [] }: ToolStatusPanelProps) {
  const [tools, setTools] = useState<ToolStatus[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchToolStatus()
  }, [])

  const fetchToolStatus = async () => {
    try {
      const res = await fetch(`${BASE_URL}/api/v1/tools/status`)
      if (res.ok) {
        const data = await res.json()
        setTools(data.tools || [])
      }
    } catch (err) {
      console.error('Failed to fetch tool status:', err)
    } finally {
      setLoading(false)
    }
  }

  const getModuleStatus = (toolName: string): string => {
    const moduleMap: Record<string, string> = {
      nuclei: 'Full Vulnerability Scan (Nuclei)',
      httpx: 'HTTP Probing & Fingerprinting',
      wapiti: 'Wapiti Vulnerability Scan',
      dalfox: 'Dalfox XSS Scan',
      corsy: 'Corsy CORS Scan',
      nikto: 'Nikto Server Scan',
      sslyze: 'SSLyze TLS Analysis',
    }
    const moduleName = moduleMap[toolName]
    if (!moduleName) return 'pending'
    
    const mod = scanModules.find(m => m.module_name === moduleName)
    if (!mod) return 'pending'
    return mod.status?.toLowerCase() || 'pending'
  }

  const statusColor = (status: string) => {
    switch (status) {
      case 'success': return 'text-emerald-400'
      case 'running': return 'text-amber-400'
      case 'failed': return 'text-red-400'
      default: return 'text-zinc-600'
    }
  }

  const statusIcon = (status: string) => {
    switch (status) {
      case 'success': return <Check className="w-3 h-3" />
      case 'running': return <Loader2 className="w-3 h-3 animate-spin" />
      case 'failed': return <X className="w-3 h-3" />
      default: return <div className="w-2 h-2 rounded-full bg-zinc-700" />
    }
  }

  if (loading) {
    return (
      <div className="p-4 space-y-3">
        <div className="flex items-center space-x-2 text-zinc-500">
          <Loader2 className="w-4 h-4 animate-spin" />
          <span className="text-[10px] font-mono uppercase tracking-widest">Checking tools...</span>
        </div>
      </div>
    )
  }

  const sortedTools = [...tools].sort((a, b) => {
    const ai = TOOL_ORDER.indexOf(a.name)
    const bi = TOOL_ORDER.indexOf(b.name)
    return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center space-x-2 text-amber-500 mb-3">
        <Wrench className="w-4 h-4" />
        <span className="text-[10px] font-mono uppercase tracking-widest font-bold">Tool Pipeline</span>
      </div>

      <div className="space-y-1">
        {sortedTools.map((tool) => {
          const status = getModuleStatus(tool.name)
          return (
            <div
              key={tool.name}
              className="flex items-center justify-between py-1.5 px-2 rounded bg-zinc-900/30 hover:bg-zinc-900/60 transition"
            >
              <div className="flex items-center space-x-2">
                <span className="text-xs">{TOOL_ICONS[tool.name] || '🔧'}</span>
                <span className="text-[11px] font-mono text-zinc-300">{tool.name}</span>
              </div>
              <div className="flex items-center space-x-2">
                {!tool.available && (
                  <span className="text-[9px] font-mono text-red-500/70">not installed</span>
                )}
                <span className={statusColor(status)}>
                  {statusIcon(status)}
                </span>
              </div>
            </div>
          )
        })}
      </div>

      {tools.some(t => !t.available) && (
        <div className="mt-4 p-3 bg-zinc-900/40 rounded border border-zinc-800">
          <p className="text-[10px] font-mono text-zinc-500 mb-2">Missing tools will be skipped. Install them for full coverage:</p>
          <div className="space-y-1">
            {tools.filter(t => !t.available).map(tool => (
              <div key={tool.name} className="text-[9px] font-mono text-zinc-600">
                <span className="text-amber-500/70">{tool.name}:</span> {tool.install_cmd}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
