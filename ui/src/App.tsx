import React, { useState, useEffect } from 'react'
import { client } from './api/client'
import { ScanProfile, ScanStatus } from './gen/scan/v1/scan_pb'
import MainLayout from './components/layout/MainLayout'
import Dashboard from './components/dashboard/Dashboard'
import EndpointMap from './components/endpoints/EndpointMap'
import ProxyHistory from './components/proxy/ProxyHistory'
import type { ProxyFlowRecord } from './components/proxy/ProxyHistory'
import HttpRepeater from './components/editor/HttpRepeater'
import FindingsBrowser from './components/findings/FindingsBrowser'
import type { FindingRecord } from './components/findings/FindingsBrowser'
import ReportGenerator from './components/reports/ReportGenerator'
import Settings from './components/settings/Settings'

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

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'endpoints' | 'proxy-history' | 'repeater' | 'findings' | 'reports' | 'ai-console' | 'settings'>('dashboard')
  
  // Dashboard & Configuration States
  const [targetUrl, setTargetUrl] = useState('http://localhost:9091')
  const [profile, setProfile] = useState<ScanProfile>(ScanProfile.STANDARD)
  const [enabledModules, setEnabledModules] = useState({
    ports: true,
    robots: true,
    headers: true,
    cookies: true,
    aiRecon: true
  })

  // Connection states
  const [goDaemonStatus, setGoDaemonStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [pythonAiStatus, setPythonAiStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  
  // Scans and events state
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [events, setEvents] = useState<ScanEventRecord[]>([])
  const [isStartingScan, setIsStartingScan] = useState(false)

  // Proxy History States
  const [flows, setFlows] = useState<ProxyFlowRecord[]>([])
  const [selectedFlow, setSelectedFlow] = useState<ProxyFlowRecord | null>(null)
  const [flowSearch, setFlowSearch] = useState('')

  // Findings Browser States
  const [findings, setFindings] = useState<FindingRecord[]>([])
  const [selectedFinding, setSelectedFinding] = useState<FindingRecord | null>(null)

  // HTTP Repeater (Editor) States
  const [repeaterHost, setRepeaterHost] = useState('httpbin.org')
  const [repeaterTls, setRepeaterTls] = useState(true)
  const [repeaterRequest, setRepeaterRequest] = useState(
    "GET /get HTTP/1.1\r\n" +
    "Host: httpbin.org\r\n" +
    "User-Agent: LastResort/0.1.0\r\n" +
    "Accept: */*\r\n" +
    "Connection: close\r\n\r\n"
  )
  const [repeaterResponse, setRepeaterResponse] = useState('')
  const [isSendingRepeater, setIsSendingRepeater] = useState(false)

  // Check health on mount and periodically
  const checkHealth = async () => {
    try {
      const res = await fetch('http://localhost:8443/health')
      if (res.ok) {
        const data = await res.json()
        setGoDaemonStatus('connected')
        if (data.ai && data.ai.status === 'ok') {
          setPythonAiStatus('connected')
        } else {
          setPythonAiStatus('disconnected')
        }
      } else {
        setGoDaemonStatus('disconnected')
        setPythonAiStatus('disconnected')
      }
    } catch {
      setGoDaemonStatus('disconnected')
      setPythonAiStatus('disconnected')
    }
  }

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 5000)
    return () => clearInterval(interval)
  }, [])

  // Fetch history and dashboard scan records
  const fetchScans = async () => {
    if (goDaemonStatus !== 'connected') return
    try {
      const res = await client.listScans({})
      const records = res.scans.map(s => ({
        id: s.scanId,
        targetUrl: s.config?.targetUrl || '',
        status: ScanStatus[s.status],
        progress: s.progress,
        profile: ScanProfile[s.config?.profile || 0],
        detectedTechnologies: s.detectedTechnologies,
        authModel: s.authModel
      }))
      setScans(records)
    } catch (err) {
      console.error('Failed to load scans:', err)
    }
  }

  // Fetch Proxy flows
  const fetchFlows = async () => {
    if (goDaemonStatus !== 'connected') return
    try {
      const res = await client.listFlows({})
      const records = res.flows.map(f => ({
        id: f.id.toString(),
        scanId: f.scanId,
        method: f.method,
        url: f.url,
        requestHeaders: f.requestHeaders,
        requestBody: new TextDecoder().decode(f.requestBody),
        responseHeaders: f.responseHeaders,
        responseBody: new TextDecoder().decode(f.responseBody),
        responseStatus: f.responseStatus,
        createdAt: new Date(f.createdAt).toLocaleTimeString()
      }))
      setFlows(records)
    } catch (err) {
      console.error('Failed to load proxy flows:', err)
    }
  }

  // Fetch security findings
  const fetchFindings = async () => {
    if (goDaemonStatus !== 'connected') return
    try {
      const res = await client.listFindings({})
      const records = res.findings.map(f => ({
        id: f.id,
        scanId: f.scanId,
        title: f.title,
        description: f.description,
        severity: f.severity,
        vulnerabilityType: f.vulnerabilityType,
        endpoint: f.endpoint,
        payload: f.payload,
        responseStatus: f.responseStatus,
        confidence: f.confidence,
        isFalsePositive: f.isFalsePositive,
        createdAt: new Date(f.createdAt).toLocaleDateString() + ' ' + new Date(f.createdAt).toLocaleTimeString()
      }))
      setFindings(records)
    } catch (err) {
      console.error('Failed to load findings:', err)
    }
  }

  const syncSystem = () => {
    checkHealth()
    fetchScans()
    fetchFlows()
    fetchFindings()
  }

  useEffect(() => {
    fetchScans()
    if (activeTab === 'proxy-history') {
      fetchFlows()
    } else if (activeTab === 'findings') {
      fetchFindings()
    }
  }, [goDaemonStatus, activeScanId, activeTab])

  // Start a new scan and subscribe to events stream
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (goDaemonStatus !== 'connected') return
    setIsStartingScan(true)
    setEvents([])

    try {
      const createRes = await client.createScan({
        config: {
          targetUrl,
          profile,
          scopePatterns: []
        }
      })
      
      const scanId = createRes.scanId
      setActiveScanId(scanId)
      addEventLog('system', `Created scan record with ID: ${scanId}`)

      await client.startScan({ scanId })
      addEventLog('system', `Dispatched scan trigger. Starting Reconnaissance...`)

      subscribeToEvents(scanId)
    } catch (err: any) {
      console.error(err)
      addEventLog('error', `Failed to start scan: ${err.message}`)
    } finally {
      setIsStartingScan(false)
    }
  }

  const addEventLog = (type: string, message: string) => {
    const time = new Date().toLocaleTimeString()
    setEvents(prev => [{ time, type, message }, ...prev])
  }

  const playChime = () => {
    try {
      const audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)()
      const osc1 = audioCtx.createOscillator()
      const gain1 = audioCtx.createGain()
      osc1.connect(gain1)
      gain1.connect(audioCtx.destination)
      osc1.frequency.setValueAtTime(523.25, audioCtx.currentTime) // C5
      gain1.gain.setValueAtTime(0.1, audioCtx.currentTime)
      gain1.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.3)
      osc1.start()
      osc1.stop(audioCtx.currentTime + 0.3)

      setTimeout(() => {
        const osc2 = audioCtx.createOscillator()
        const gain2 = audioCtx.createGain()
        osc2.connect(gain2)
        gain2.connect(audioCtx.destination)
        osc2.frequency.setValueAtTime(659.25, audioCtx.currentTime) // E5
        gain2.gain.setValueAtTime(0.1, audioCtx.currentTime)
        gain2.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.4)
        osc2.start()
        osc2.stop(audioCtx.currentTime + 0.4)
      }, 150)

      setTimeout(() => {
        const osc3 = audioCtx.createOscillator()
        const gain3 = audioCtx.createGain()
        osc3.connect(gain3)
        gain3.connect(audioCtx.destination)
        osc3.frequency.setValueAtTime(783.99, audioCtx.currentTime) // G5
        gain3.gain.setValueAtTime(0.15, audioCtx.currentTime)
        gain3.gain.exponentialRampToValueAtTime(0.01, audioCtx.currentTime + 0.6)
        osc3.start()
        osc3.stop(audioCtx.currentTime + 0.6)
      }, 300)
    } catch (e) {
      console.error(e)
    }
  }

  const subscribeToEvents = async (scanId: string) => {
    try {
      for await (const event of client.streamScanEvents({ scanId })) {
        let msg = ''
        const fields = event.data?.fields as any
        if (event.eventType === 'phase.started') {
          msg = `Phase [${fields?.phase?.kind?.value}] started.`
        } else if (event.eventType === 'progress.update') {
          msg = `Progress: ${(Number(fields?.progress?.kind?.value || 0) * 100).toFixed(0)}%`
        } else if (event.eventType === 'finding.new') {
          msg = `[FINDING DISCOVERED] Title: "${fields?.title?.kind?.value}" | Severity: ${fields?.severity?.kind?.value}`
        } else if (event.eventType === 'hypothesis.generated') {
          msg = `[HYPOTHESIS] "${fields?.title?.kind?.value}" (confidence: ${Number(fields?.confidence?.kind?.value || 0).toFixed(2)})`
        } else if (event.eventType === 'log.info' || event.eventType === 'log.warning' || event.eventType === 'log.error') {
          msg = `${fields?.message?.kind?.value || ''}`
        } else if (event.eventType === 'module.error') {
          msg = `Module [${fields?.phase?.kind?.value}] error: ${fields?.error?.kind?.value}`
        } else if (event.eventType === 'phase.completed') {
          msg = `Phase [${fields?.phase?.kind?.value}] completed successfully.`
        }
        addEventLog(event.eventType, msg)
      }
      addEventLog('system', `Orchestrator completed scan workflow successfully.`)
      playChime()
      fetchScans()
    } catch (err: any) {
      addEventLog('error', `Stream closed: ${err.message}`)
    }
  }

  // Send Repeater Request
  const handleSendRepeater = async () => {
    if (goDaemonStatus !== 'connected') return
    setIsSendingRepeater(true)
    setRepeaterResponse('')
    try {
      const res = await client.sendRepeaterRequest({
        rawRequest: repeaterRequest,
        targetHost: repeaterHost,
        useTls: repeaterTls
      })
      setRepeaterResponse(res.rawResponse)
    } catch (err: any) {
      setRepeaterResponse(`[ERROR] Connection failed:\n${err.message}`)
    } finally {
      setIsSendingRepeater(false)
    }
  }

  const handleSendToRepeater = (host: string, useTls: boolean, request: string) => {
    setRepeaterHost(host)
    setRepeaterTls(useTls)
    setRepeaterRequest(request)
    setActiveTab('repeater')
  }

  return (
    <MainLayout
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      goDaemonStatus={goDaemonStatus}
      pythonAiStatus={pythonAiStatus}
      targetUrl={targetUrl}
      onSync={syncSystem}
    >
      {activeTab === 'dashboard' && (
        <Dashboard
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          profile={profile}
          setProfile={setProfile}
          enabledModules={enabledModules}
          setEnabledModules={setEnabledModules}
          goDaemonStatus={goDaemonStatus}
          isStartingScan={isStartingScan}
          handleStartScan={handleStartScan}
          events={events}
          scans={scans}
          setActiveScanId={setActiveScanId}
          subscribeToEvents={subscribeToEvents}
        />
      )}

      {activeTab === 'endpoints' && (
        <EndpointMap activeScanId={activeScanId} />
      )}

      {activeTab === 'proxy-history' && (
        <ProxyHistory
          flows={flows}
          selectedFlow={selectedFlow}
          setSelectedFlow={setSelectedFlow}
          flowSearch={flowSearch}
          setFlowSearch={setFlowSearch}
          onSendToRepeater={handleSendToRepeater}
        />
      )}

      {activeTab === 'repeater' && (
        <HttpRepeater
          repeaterHost={repeaterHost}
          setRepeaterHost={setRepeaterHost}
          repeaterTls={repeaterTls}
          setRepeaterTls={setRepeaterTls}
          repeaterRequest={repeaterRequest}
          setRepeaterRequest={setRepeaterRequest}
          repeaterResponse={repeaterResponse}
          isSendingRepeater={isSendingRepeater}
          handleSendRepeater={handleSendRepeater}
        />
      )}

      {activeTab === 'findings' && (
        <FindingsBrowser
          findings={findings}
          selectedFinding={selectedFinding}
          setSelectedFinding={setSelectedFinding}
        />
      )}

      {activeTab === 'reports' && (
        <ReportGenerator activeScanId={activeScanId} />
      )}

      {activeTab === 'settings' && (
        <Settings />
      )}
    </MainLayout>
  )
}
