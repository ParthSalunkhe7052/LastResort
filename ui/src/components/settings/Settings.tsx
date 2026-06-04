import React, { useState, useEffect } from 'react'
import { Sliders, Cpu, Layers, Check, AlertTriangle, ShieldCheck, Loader2 } from 'lucide-react'

export default function Settings() {
  const [aiProvider, setAiProvider] = useState('gemini')
  const [geminiModel, setGeminiModel] = useState('gemini-3.5-flash')
  const [isLoading, setIsLoading] = useState(true)
  const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle')
  const [errorMessage, setErrorMessage] = useState('')

  useEffect(() => {
    fetchSettings()
  }, [])

  const fetchSettings = async () => {
    try {
      setIsLoading(true)
      const res = await fetch('http://127.0.0.1:8443/api/v1/settings')
      if (res.ok) {
        const data = await res.json()
        if (data.settings) {
          setAiProvider(data.settings.ai_provider || 'gemini')
          setGeminiModel(data.settings.gemini_model || 'gemini-3.5-flash')
        }
      } else {
        setErrorMessage('Failed to fetch configurations from Go backend daemon.')
      }
    } catch (err: any) {
      setErrorMessage(`Network error fetching settings: ${err.message}`)
    } finally {
      setIsLoading(false)
    }
  }

  const updateSetting = async (key: string, value: string) => {
    try {
      setSaveStatus('saving')
      const res = await fetch('http://127.0.0.1:8443/api/v1/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, value })
      })
      if (res.ok) {
        setSaveStatus('saved')
        setTimeout(() => setSaveStatus('idle'), 2000)
      } else {
        const data = await res.json()
        setErrorMessage(data.error || 'Failed to update setting.')
        setSaveStatus('error')
      }
    } catch (err: any) {
      setErrorMessage(`Network error saving setting: ${err.message}`)
      setSaveStatus('error')
    }
  }

  const handleProviderChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value
    setAiProvider(val)
    updateSetting('ai_provider', val)
  }

  const handleModelChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const val = e.target.value
    setGeminiModel(val)
    updateSetting('gemini_model', val)
  }

  if (isLoading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="flex flex-col items-center space-y-4">
          <Loader2 className="w-8 h-8 text-amber-500 animate-spin" />
          <span className="font-mono text-xs text-zinc-500">Retrieving system config...</span>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-4xl space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-300">
      
      {/* Title & Stats Banner */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between border-b border-zinc-900 pb-6 gap-4">
        <div>
          <h2 className="text-xl font-bold text-zinc-50 flex items-center space-x-2 tracking-wide font-mono">
            <Sliders className="w-5 h-5 text-amber-500" />
            <span>AI ENGINE CONFIGURATION</span>
          </h2>
          <p className="text-xs text-zinc-500 mt-1 font-mono">Configure the neural network parameters and LLM model bindings.</p>
        </div>

        {/* Dynamic Saving Notification Status */}
        <div className="flex items-center">
          {saveStatus === 'saving' && (
            <div className="flex items-center space-x-2 bg-zinc-900 border border-zinc-800 text-zinc-400 px-3 py-1.5 rounded-lg text-xs font-mono">
              <Loader2 className="w-3 h-3 animate-spin text-amber-500" />
              <span>Auto-saving modifications...</span>
            </div>
          )}
          {saveStatus === 'saved' && (
            <div className="flex items-center space-x-2 bg-emerald-950/40 border border-emerald-900/60 text-emerald-400 px-3 py-1.5 rounded-lg text-xs font-mono shadow-[0_0_10px_rgba(16,185,129,0.05)]">
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              <span>Config updated and persisted</span>
            </div>
          )}
          {saveStatus === 'error' && (
            <div className="flex items-center space-x-2 bg-rose-950/40 border border-rose-900/60 text-rose-400 px-3 py-1.5 rounded-lg text-xs font-mono">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              <span>Update failed: {errorMessage}</span>
            </div>
          )}
        </div>
      </div>

      {errorMessage && saveStatus !== 'error' && (
        <div className="bg-rose-950/20 border border-rose-900/40 text-rose-400 p-4 rounded-lg text-xs font-mono flex items-start space-x-3">
          <AlertTriangle className="w-4 h-4 mt-0.5 shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Main Form Fields */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        
        {/* Card: LLM Provider Select */}
        <div className="border border-zinc-900 bg-zinc-900/20 rounded-xl p-6 space-y-4 hover:border-zinc-800 transition duration-350">
          <div className="flex items-center space-x-3">
            <Cpu className="w-5 h-5 text-amber-500/80" />
            <h3 className="font-semibold text-sm text-zinc-100 font-mono tracking-wider">INTELLIGENCE PROVIDER</h3>
          </div>
          <p className="text-[11px] text-zinc-500 font-mono leading-relaxed">
            Select the artificial intelligence backend. Changing this dynamically redirects all reconnaissance, exploit payload generation, and verification engines.
          </p>
          
          <div className="pt-2">
            <label className="block text-[10px] font-mono text-zinc-500 mb-2 uppercase tracking-wider">Active Core Provider</label>
            <select
              value={aiProvider}
              onChange={handleProviderChange}
              className="w-full bg-zinc-950 border border-zinc-850 rounded-lg px-4 py-3 text-zinc-100 font-mono text-xs focus:outline-none focus:border-amber-500 transition cursor-pointer"
            >
              <option value="gemini">Google Gemini AI (Cloud API)</option>
              <option value="mock">Offline Mock Agent (Local, Free)</option>
              <option value="ollama">Ollama Local Instance (Self-Hosted)</option>
            </select>
          </div>
        </div>

        {/* Card: Gemini Specific Settings */}
        <div className={`border border-zinc-900 bg-zinc-900/20 rounded-xl p-6 space-y-4 hover:border-zinc-800 transition duration-350 ${
          aiProvider !== 'gemini' ? 'opacity-40 pointer-events-none' : ''
        }`}>
          <div className="flex items-center space-x-3">
            <Layers className="w-5 h-5 text-amber-500/80" />
            <h3 className="font-semibold text-sm text-zinc-100 font-mono tracking-wider">GEMINI MODEL OVERRIDE</h3>
          </div>
          <p className="text-[11px] text-zinc-500 font-mono leading-relaxed">
            Specify the cloud Gemini model configuration. Gemini 3.5 Flash is recommended for balanced execution cost, performance, and low token utilization.
          </p>

          <div className="pt-2">
            <label className="block text-[10px] font-mono text-zinc-500 mb-2 uppercase tracking-wider">Target API Model</label>
            <select
              value={geminiModel}
              onChange={handleModelChange}
              disabled={aiProvider !== 'gemini'}
              className="w-full bg-zinc-950 border border-zinc-850 rounded-lg px-4 py-3 text-zinc-100 font-mono text-xs focus:outline-none focus:border-amber-500 transition cursor-pointer disabled:cursor-not-allowed"
            >
              <option value="gemini-3.5-flash">Gemini 3.5 Flash (Recommended)</option>
              <option value="gemini-2.5-flash">Gemini 2.5 Flash</option>
            </select>
          </div>
        </div>

      </div>

      {/* Warning/Info Box */}
      <div className="bg-zinc-900/30 border border-zinc-900 rounded-xl p-6 flex items-start space-x-4">
        <ShieldCheck className="w-5 h-5 text-amber-500/60 mt-0.5 shrink-0 animate-pulse" />
        <div className="space-y-1.5">
          <h4 className="text-xs font-semibold text-zinc-300 font-mono">AUTOMATED API KEY CYCLING</h4>
          <p className="text-[11px] text-zinc-500 font-mono leading-relaxed">
            The daemon has detected backup keys configured in the env: <code className="text-zinc-400 font-mono bg-zinc-950/60 px-1 py-0.5 rounded">GEMINI_BACKUP_KEYS</code>. 
            If your active API key hits a rate limit (429) or quota restriction (403), the engine will automatically failover to backups in real-time. No restart needed.
          </p>
        </div>
      </div>

    </div>
  )
}
