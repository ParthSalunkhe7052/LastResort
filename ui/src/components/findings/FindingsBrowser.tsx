import { useState } from 'react'
import { ShieldCheck, Search, Zap, Microscope, ChevronDown, ChevronRight, Code, Terminal, Play, Clipboard } from 'lucide-react'

export interface FindingRecord {
  id: string
  scanId: string
  title: string
  description: string
  severity: string
  vulnerabilityType: string
  endpoint: string
  payload: string
  responseStatus: number
  confidence: number
  category: string
  isFalsePositive: boolean
  createdAt: string
}

interface FindingsBrowserProps {
  findings: FindingRecord[]
  selectedFinding: FindingRecord | null
  setSelectedFinding: (finding: FindingRecord | null) => void
}

export default function FindingsBrowser({
  findings,
  selectedFinding,
  setSelectedFinding
}: FindingsBrowserProps) {
  const [activeTab, setActiveTab] = useState<'evidence' | 'request' | 'response' | 'playwright' | 'curl'>('evidence')
  const [isTechExpanded, setIsTechExpanded] = useState(false)

  const categories = [
    { id: 'VERIFIED_ATTACK', label: 'Verified Attacks', icon: Zap, color: 'text-rose-500', bg: 'bg-rose-500/10' },
    { id: 'ATTEMPT', label: 'Failed Attack Attempts', icon: ShieldCheck, color: 'text-zinc-400', bg: 'bg-zinc-800' },
    { id: 'OBSERVATION', label: 'Security Observations', icon: Microscope, color: 'text-sky-500', bg: 'bg-sky-500/10' },
    { id: 'HYPOTHESIS', label: 'AI Hypotheses', icon: Search, color: 'text-amber-500', bg: 'bg-amber-500/10' },
  ]

  const getConfidenceLabel = (conf: number) => {
    if (conf >= 0.9) return { label: 'HIGH', color: 'text-emerald-500' }
    if (conf >= 0.7) return { label: 'MEDIUM', color: 'text-amber-500' }
    if (conf >= 0.4) return { label: 'LOW', color: 'text-rose-500' }
    return { label: 'UNKNOWN', color: 'text-zinc-500' }
  }

  const getBeginnerVerification = (f: FindingRecord) => {
    if (f.vulnerabilityType === 'Security Misconfiguration') {
      const header = f.title.split(': ')[1]
      return [
        "1. Open your browser (Chrome or Firefox).",
        `2. Visit ${f.endpoint}`,
        "3. Right-click anywhere and select 'Inspect'.",
        "4. Click on the 'Network' tab.",
        "5. Reload the page (press F5).",
        "6. Select the first item in the list (the main page).",
        "7. Scroll down to 'Response Headers' on the right.",
        `8. Confirm the '${header}' header is missing from the list.`
      ]
    }
    if (f.vulnerabilityType === 'Reflected XSS') {
      return [
        "1. Copy the payload provided in the details below.",
        `2. Paste it into the URL parameter at ${f.endpoint}`,
        "3. Press Enter.",
        "4. Check if an alert box appears or if the code is visible in the page source."
      ]
    }
    return ["1. Manual verification required by a security engineer.", "2. Review the technical evidence and raw traffic below."]
  }

  return (
    <div className="flex-1 flex gap-6 overflow-hidden">
      {/* Findings list grouped by category */}
      <div className="flex-1 border border-zinc-800 bg-zinc-900/10 rounded-xl flex flex-col overflow-hidden">
        <div className="px-6 py-4 border-b border-zinc-800 bg-zinc-900/40 shrink-0">
          <h3 className="font-semibold text-sm flex items-center space-x-2 text-zinc-100">
            <Microscope className="w-4 h-4 text-zinc-400" />
            <span>Security Assessment Findings</span>
          </h3>
        </div>

        <div className="flex-1 overflow-y-auto custom-scrollbar p-4 space-y-6">
          {findings.length === 0 ? (
            <div className="p-12 text-center italic text-zinc-600 text-xs">No audit findings recorded. Start a scan to begin exploration.</div>
          ) : (
            categories.map(cat => {
              const catFindings = findings.filter(f => (f.category || 'OBSERVATION') === cat.id)
              if (catFindings.length === 0) return null

              return (
                <div key={cat.id} className="space-y-3">
                  <div className="flex items-center space-x-2 px-2">
                    <cat.icon className={`w-3.5 h-3.5 ${cat.color}`} />
                    <span className="text-[10px] font-bold tracking-widest text-zinc-500 uppercase">{cat.label}</span>
                    <span className="text-[10px] bg-zinc-800 text-zinc-400 px-1.5 py-0.5 rounded-full">{catFindings.length}</span>
                  </div>
                  <div className="space-y-1">
                    {catFindings.map(f => (
                      <div 
                        key={f.id}
                        onClick={() => {
                          setSelectedFinding(f)
                          setIsTechExpanded(false)
                        }}
                        className={`group p-3 rounded-lg border transition cursor-pointer flex items-center justify-between ${
                          selectedFinding?.id === f.id 
                            ? 'bg-zinc-800/60 border-zinc-600 shadow-lg' 
                            : 'bg-zinc-900/20 border-zinc-800/60 hover:border-zinc-700 hover:bg-zinc-900/40'
                        }`}
                      >
                        <div className="flex-1 min-w-0 pr-4">
                          <div className="flex items-center space-x-2 mb-1">
                            <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                              f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' :
                              f.severity === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                              'bg-zinc-800 border-zinc-700 text-zinc-500'
                            }`}>{f.severity}</span>
                            <h4 className={`text-xs font-semibold truncate ${selectedFinding?.id === f.id ? 'text-zinc-100' : 'text-zinc-400 group-hover:text-zinc-200'}`}>{f.title}</h4>
                          </div>
                          <p className="text-[10px] text-zinc-600 truncate font-mono">{f.endpoint}</p>
                        </div>
                        <ChevronRight className={`w-4 h-4 transition ${selectedFinding?.id === f.id ? 'text-zinc-400 translate-x-1' : 'text-zinc-700 group-hover:text-zinc-500'}`} />
                      </div>
                    ))}
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>

      {/* Finding Detail Pane */}
      <div className="w-[500px] border border-zinc-800 bg-zinc-950 rounded-xl flex flex-col overflow-hidden shrink-0">
        {selectedFinding ? (
          <div className="flex-1 overflow-y-auto custom-scrollbar flex flex-col">
            <div className="p-6 border-b border-zinc-800 bg-zinc-900/20 space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${
                    selectedFinding.severity === 'HIGH' || selectedFinding.severity === 'CRITICAL' ? 'bg-rose-500/10 border-rose-500/20 text-rose-400' :
                    selectedFinding.severity === 'MEDIUM' ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' :
                    'bg-zinc-800 border-zinc-700 text-zinc-500'
                  }`}>{selectedFinding.severity}</span>
                  <span className="text-[9px] text-zinc-500 font-mono">Evidence Confidence: <span className={`font-bold ${getConfidenceLabel(selectedFinding.confidence).color}`}>{getConfidenceLabel(selectedFinding.confidence).label}</span></span>
                </div>
                <span className="text-[10px] text-zinc-600 font-mono">{selectedFinding.createdAt}</span>
              </div>
              <h4 className="font-bold text-lg text-zinc-100 leading-tight">{selectedFinding.title}</h4>
              <p className="text-[11px] text-amber-500/80 font-mono bg-amber-500/5 px-2 py-1 rounded border border-amber-500/10 inline-block">{selectedFinding.endpoint}</p>
            </div>

            <div className="p-6 space-y-8 flex-1">
              {/* Reality Description */}
              <section className="space-y-3">
                <div className="flex items-center space-x-2 text-[10px] font-bold tracking-widest text-zinc-500 uppercase">
                  <Zap className="w-3.5 h-3.5" />
                  <span>The Situation</span>
                </div>
                <div className="p-4 bg-zinc-900/40 border border-zinc-800 rounded-lg">
                  <p className="text-xs text-zinc-300 leading-relaxed whitespace-pre-wrap">{selectedFinding.description}</p>
                </div>
              </section>

              {/* Beginner Verification */}
              <section className="space-y-3">
                <div className="flex items-center space-x-2 text-[10px] font-bold tracking-widest text-zinc-500 uppercase">
                  <ShieldCheck className="w-3.5 h-3.5" />
                  <span>How to Verify (Beginner Guide)</span>
                </div>
                <div className="p-4 bg-emerald-500/5 border border-emerald-500/10 rounded-lg space-y-2">
                  {getBeginnerVerification(selectedFinding).map((step, i) => (
                    <p key={i} className="text-[11px] text-emerald-400/90 flex items-start">
                      <span className="mr-2 mt-0.5">•</span>
                      <span>{step}</span>
                    </p>
                  ))}
                </div>
              </section>

              {/* Collapsible Technical Details */}
              <section className="space-y-3">
                <button 
                  type="button"
                  onClick={() => setIsTechExpanded(!isTechExpanded)}
                  className="w-full flex items-center justify-between group"
                >
                  <div className="flex items-center space-x-2 text-[10px] font-bold tracking-widest text-zinc-500 uppercase">
                    <Code className="w-3.5 h-3.5" />
                    <span>Technical Evidence</span>
                  </div>
                  {isTechExpanded ? <ChevronDown className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400" /> : <ChevronRight className="w-4 h-4 text-zinc-600 group-hover:text-zinc-400" />}
                </button>

                {isTechExpanded && (
                  <div className="border border-zinc-800 rounded-lg overflow-hidden bg-zinc-950">
                    <div className="flex border-b border-zinc-800 bg-zinc-900/40">
                      {[
                        { id: 'evidence', label: 'Payload', icon: Zap },
                        { id: 'request', label: 'Request', icon: Terminal },
                        { id: 'response', label: 'Response', icon: Clipboard },
                        { id: 'playwright', label: 'Playwright', icon: Play },
                        { id: 'curl', label: 'cURL', icon: Terminal },
                      ].map(tab => (
                        <button
                          type="button"
                          key={tab.id}
                          onClick={() => setActiveTab(tab.id as any)}
                          className={`px-3 py-2 text-[10px] font-mono flex items-center space-x-1.5 transition ${
                            activeTab === tab.id ? 'bg-zinc-800 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'
                          }`}
                        >
                          <tab.icon className="w-3 h-3" />
                          <span>{tab.label}</span>
                        </button>
                      ))}
                    </div>
                    <div className="p-4 min-h-[200px] max-h-[400px] overflow-auto custom-scrollbar bg-zinc-950 font-mono text-[11px]">
                      {activeTab === 'evidence' && (
                        <pre className="text-amber-400">{selectedFinding.payload || 'No specific payload evidence for this observation.'}</pre>
                      )}
                      {activeTab === 'request' && (
                        <pre className="text-zinc-400">Loading raw HTTP request flow from database...</pre>
                      )}
                      {activeTab === 'response' && (
                        <pre className="text-zinc-400">Loading raw HTTP response flow from database...</pre>
                      )}
                      {activeTab === 'playwright' && (
                        <div className="text-zinc-500 italic">No automated browser script available for this finding.</div>
                      )}
                      {activeTab === 'curl' && (
                        <div className="group relative">
                          <pre className="text-sky-400">curl -X GET "{selectedFinding.endpoint}" \
  -H "User-Agent: LastResort/0.1.0" \
  -H "Accept: */*"</pre>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </section>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-zinc-700 text-center p-12 space-y-4">
            <Microscope className="w-12 h-12 text-zinc-800" />
            <div className="space-y-1">
              <p className="text-sm font-semibold text-zinc-600">No Finding Selected</p>
              <p className="text-[11px] italic">Select an item from the sidebar to inspect verified evidence and remediation steps.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

