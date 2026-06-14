import React, { useState, useEffect } from 'react'
import { client, BASE_URL } from './api/client'
import MainLayout from './components/layout/MainLayout'
import Dashboard from './components/dashboard/Dashboard'
import Settings from './components/settings/Settings'

interface ScanEventRecord {
  time: string
  type: string
  message: string
}

export default function App() {

  // Dashboard & Configuration States
  const [targetUrl, setTargetUrl] = useState('https://demo.testfire.net/')
  const [authCookie, setAuthCookie] = useState('')
  const [scopePatternsText, setScopePatternsText] = useState('')
  const [scanProfile, setScanProfile] = useState<number>(2) // Standard by default
  const [activeTab, setActiveTab] = useState<'dashboard' | 'settings'>('dashboard')

  // Connection states
  const [goDaemonStatus, setGoDaemonStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')
  const [aiEngineStatus, setAiEngineStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting')

  // Scans and events state
  const [activeScanId, setActiveScanId] = useState<string | null>(null)
  const [events, setEvents] = useState<ScanEventRecord[]>([])
  const [isStartingScan, setIsStartingScan] = useState(false)
  const [scanStatus, setScanStatus] = useState<string>('IDLE')

  // Manual Guide State
  const [manualGuide, setManualGuide] = useState<string | null>(null)

  // Testing Mode State (1=automated, 2=manual)
  const [testingMode, setTestingMode] = useState<number>(1)


  // Scan Modules State
  const [scanModules, setScanModules] = useState<any[]>([])

  // Live Browser Streaming State
  const [liveScreenshot, setLiveScreenshot] = useState<string | null>(null)

  // Performance Summary State
  const [performanceMetrics, setPerformanceMetrics] = useState<any>(null)

  // Verification & Evidence State
  const [verifications, setVerifications] = useState<any[]>([])

  // Final Report State
  const [reportUrl, setReportUrl] = useState<string | null>(null)

  // Check health on mount and periodically
  const checkHealth = async () => {
    try {
      const res = await fetch(`${BASE_URL}/health`)
      if (res.ok) {
        const data = await res.json()
        setGoDaemonStatus('connected')
        if (data.ai && data.ai.status === 'ok') {
          setAiEngineStatus('connected')
        } else {
          setAiEngineStatus('disconnected')
        }
      } else {
        setGoDaemonStatus('disconnected')
        setAiEngineStatus('disconnected')
      }
    } catch {
      setGoDaemonStatus('disconnected')
      setAiEngineStatus('disconnected')
    }
  }

  useEffect(() => {
    checkHealth()
    const interval = setInterval(checkHealth, 5000)
    return () => clearInterval(interval)
  }, [])

  // Fetch security findings
  // fetchFindings was here

  // Fetch verifications
  const fetchVerifications = async () => {
    if (!activeScanId || goDaemonStatus !== 'connected') return
    try {
      const res = await fetch(`${BASE_URL}/api/v1/verifications?scan_id=${activeScanId}`)
      if (res.ok) {
        const data = await res.json()
        setVerifications(data.verifications || [])
      }
    } catch (err) {
      console.error('Failed to load verifications:', err)
    }
  }


  const fetchScanModules = async () => {
    if (!activeScanId || goDaemonStatus !== 'connected') return
    try {
      const res = await fetch(`${BASE_URL}/api/v1/scan-modules?scan_id=${activeScanId}`)
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
      const res = await fetch(`${BASE_URL}/api/v1/scan/performance?scan_id=${activeScanId}`)
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
    fetchVerifications()
    fetchScanModules()
    fetchPerformanceMetrics()
  }

  useEffect(() => {
    if (activeScanId) {
      fetchVerifications()
      fetchScanModules()
      fetchPerformanceMetrics()
    }
  }, [goDaemonStatus, activeScanId])

  // Start a new scan and subscribe to events stream
  const handleStartScan = async (e: React.FormEvent, testingModeParam: number = 1) => {
    e.preventDefault()
    if (goDaemonStatus !== 'connected') return
    setIsStartingScan(true)
    setEvents([])
    setLiveScreenshot(null)
    setVerifications([])
    setReportUrl(null)
    setManualGuide(null)
    setTestingMode(testingModeParam)

    const scopePatterns = scopePatternsText
      .split('\n')
      .map(p => p.trim())
      .filter(p => p !== '')

    try {
      const createRes = await client.createScan({
        config: {
          targetUrl,
          profile: scanProfile,
          scopePatterns: scopePatterns,
          authCookies: authCookie,
          testingMode: testingModeParam
        }
      })

      const scanId = createRes.scanId
      setActiveScanId(scanId)
      setScanStatus('RUNNING')
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
          fetchVerifications()
        } else if (event.eventType === 'hypothesis.generated') {
          msg = `[HYPOTHESIS] "${fields?.title?.kind?.value}" (confidence: ${Number(fields?.confidence?.kind?.value || 0).toFixed(2)})`
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
        } else if (event.eventType === 'manual.guide.ready') {
          const guide = fields?.guide?.kind?.value || ''
          setManualGuide(guide)
          msg = `Manual Testing Guide is now available.`
        } else if (event.eventType === 'report.generated') {
          const path = fields?.path?.kind?.value || ''
          const url = `${BASE_URL}/${path}`
          setReportUrl(url)
          msg = `Final assessment report generated: ${url}`
        }
        addEventLog(event.eventType, msg)
        if (event.eventType === 'scan.completed') {
          setScanStatus('COMPLETED')
        } else if (event.eventType === 'scan.failed') {
          setScanStatus('FAILED')
        }
      }
      addEventLog('system', `Orchestrator completed scan workflow successfully.`)
      playChime()
      setScanStatus('COMPLETED')
      fetchScanModules()
      fetchVerifications()
      fetchPerformanceMetrics()
    } catch (err: any) {
      addEventLog('error', `Stream closed: ${err.message}`)
      setScanStatus('FAILED')
    }
  }

  const getActiveObjective = () => {
    if (!activeScanId) return "Awaiting target specification"
    const runningModule = scanModules.find(m => m.status === 'RUNNING')
    if (runningModule) return runningModule.module_name

    if (scanStatus === 'COMPLETED') return "Simulation Completed. Report generated."
    if (scanStatus === 'FAILED') return "Simulation Failed."
    if (isStartingScan) return "Spawning Penetration Rig..."

    return "Analyzing Target Application"
  }

  return (
    <MainLayout
      activeTab={activeTab}
      setActiveTab={setActiveTab}
      goDaemonStatus={goDaemonStatus}
      aiEngineStatus={aiEngineStatus}
      targetUrl={targetUrl}
      onSync={syncSystem}
      scanStatus={scanStatus}
      currentObjective={getActiveObjective()}
    >
      {activeTab === 'dashboard' ? (
        <Dashboard
          targetUrl={targetUrl}
          setTargetUrl={setTargetUrl}
          authCookie={authCookie}
          setAuthCookie={setAuthCookie}
          scopePatternsText={scopePatternsText}
          setScopePatternsText={setScopePatternsText}
          scanProfile={scanProfile}
          setScanProfile={setScanProfile}
          goDaemonStatus={goDaemonStatus}
          isStartingScan={isStartingScan}
          handleStartScan={handleStartScan}
          events={events}
          scanModules={scanModules}
          activeScanId={activeScanId}
          liveScreenshot={liveScreenshot}
          performanceMetrics={performanceMetrics}
          verifications={verifications}
          reportUrl={reportUrl}
          manualGuide={manualGuide}
          testingMode={testingMode}
        />
      ) : (
        <Settings />
      )}
    </MainLayout>
  )
}
