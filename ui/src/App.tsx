import React, { useState, useEffect } from 'react'
import { client } from './api/client'
import { ScanProfile, ScanStatus } from './gen/scan/v1/scan_pb'
import MainLayout from './components/layout/MainLayout'
import Dashboard from './components/dashboard/Dashboard'
import Settings from './components/settings/Settings'
import type { FindingRecord } from './components/findings/FindingsBrowser'


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
  
  // Dashboard & Configuration States
  const [targetUrl, setTargetUrl] = useState('https://owasp.org/www-project-juice-shop/')
  const [activeTab, setActiveTab] = useState<'dashboard' | 'settings'>('dashboard')

  // Connection states
  const [goDaemonStatus, setGoDaemonStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [pythonAiStatus, setPythonAiStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  
  // Scans and events state
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [scans, setScans] = useState<ScanRecord[]>([])
  const [events, setEvents] = useState<ScanEventRecord[]>([])
  const [isStartingScan, setIsStartingScan] = useState(false)

  // Findings Browser States
  const [findings, setFindings] = useState<FindingRecord[]>([])

  // Hypotheses State
  const [hypotheses, setHypotheses] = useState<any[]>([])

  // Scan Modules State
  const [scanModules, setScanModules] = useState<any[]>([])

  // Live Browser Streaming State
  const [liveScreenshot, setLiveScreenshot] = useState<string | null>(null)

  // Performance Summary State
  const [performanceMetrics, setPerformanceMetrics] = useState<any>(null)


  // Check health on mount and periodically
  const checkHealth = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8443/health')
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
        category: f.category,
        isFalsePositive: f.isFalsePositive,
        createdAt: new Date(f.createdAt).toLocaleDateString() + ' ' + new Date(f.createdAt).toLocaleTimeString()
      }))
      setFindings(records)
    } catch (err) {
      console.error('Failed to load findings:', err)
    }
  }

  // Fetch hypotheses
  const fetchHypotheses = async () => {
    if (!activeScanId || goDaemonStatus !== 'connected') return
    try {
      const res = await fetch(`http://127.0.0.1:8443/api/v1/hypotheses?scan_id=${activeScanId}`)
      if (res.ok) {
        const data = await res.json()
        setHypotheses(data.hypotheses || [])
      }
    } catch (err) {
      console.error('Failed to load hypotheses:', err)
    }
  }

  const fetchScanModules = async () => {
    if (!activeScanId || goDaemonStatus !== 'connected') return
    try {
      const res = await fetch(`http://127.0.0.1:8443/api/v1/scan-modules?scan_id=${activeScanId}`)
      if (res.ok) {
        const data = await res.json()
        setScanModules(data.modules || [])
      }
    } catch (err) {
      console.error('Failed to load scan modules:', err)
    }
  }

  const fetchPerformanceMetrics = async () => {
    if (!activeScanId || goDaemonStatus !== 'connected') return
    try {
      const res = await fetch(`http://127.0.0.1:8443/api/v1/scan/performance?scan_id=${activeScanId}`)
      if (res.ok) {
        const data = await res.json()
        setPerformanceMetrics(data)
      }
    } catch (err) {
      console.error('Failed to load performance metrics:', err)
    }
  }

  const syncSystem = () => {
    checkHealth()
    fetchScans()
    fetchFindings()
    fetchHypotheses()
    fetchScanModules()
    fetchPerformanceMetrics()
  }

  useEffect(() => {
    fetchScans()
    fetchFindings()
    if (activeScanId) {
      fetchHypotheses()
      fetchScanModules()
      fetchPerformanceMetrics()
    }
  }, [goDaemonStatus, activeScanId])

  // Start a new scan and subscribe to events stream
  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault()
    if (goDaemonStatus !== 'connected') return
    setIsStartingScan(true)
    setEvents([])
    setLiveScreenshot(null)

    try {
      const createRes = await client.createScan({
        config: {
          targetUrl,
          profile: ScanProfile.STANDARD,
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
          fetchScanModules()
        } else if (event.eventType === 'progress.update') {
          msg = `Progress: ${(Number(fields?.progress?.kind?.value || 0) * 100).toFixed(0)}%`
        } else if (event.eventType === 'finding.new') {
          msg = `[FINDING DISCOVERED] Title: "${fields?.title?.kind?.value}" | Severity: ${fields?.severity?.kind?.value}`
          fetchFindings()
        } else if (event.eventType === 'hypothesis.generated') {
          msg = `[HYPOTHESIS] "${fields?.title?.kind?.value}" (confidence: ${Number(fields?.confidence?.kind?.value || 0).toFixed(2)})`
          fetchHypotheses()
        } else if (event.eventType === 'log.info' || event.eventType === 'log.warning' || event.eventType === 'log.error') {
          msg = `${fields?.message?.kind?.value || ''}`
        } else if (event.eventType === 'module.error') {
          msg = `Module [${fields?.phase?.kind?.value}] error: ${fields?.error?.kind?.value}`
          fetchScanModules()
        } else if (event.eventType === 'phase.completed') {
          msg = `Phase [${fields?.phase?.kind?.value}] completed successfully.`
          fetchScanModules()
        } else if (event.eventType === 'browser.screenshot') {
          const img = fields?.image?.kind?.value || ''
          setLiveScreenshot(img)
          continue
        }
        addEventLog(event.eventType, msg)
      }
      addEventLog('system', `Orchestrator completed scan workflow successfully.`)
      playChime()
      fetchScans()
      fetchScanModules()
      fetchFindings()
      fetchPerformanceMetrics()
    } catch (err: any) {
      addEventLog('error', `Stream closed: ${err.message}`)
    }
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
      {activeTab === 'dashboard' ? (
        <Dashboard
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          goDaemonStatus={goDaemonStatus}
          isStartingScan={isStartingScan}
          handleStartScan={handleStartScan}
          events={events}
          scans={scans}
          setActiveScanId={setActiveScanId}
          subscribeToEvents={subscribeToEvents}
          scanModules={scanModules}
          activeScanId={activeScanId}
          findings={findings}
          hypotheses={hypotheses}
          liveScreenshot={liveScreenshot}
          performanceMetrics={performanceMetrics}
        />
      ) : (
        <Settings />
      )}
    </MainLayout>
  )
}
