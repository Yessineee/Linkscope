/* global chrome */

import { useEffect, useState } from 'react'
import { Shield, ShieldAlert, ShieldCheck, ShieldX, RefreshCw, ExternalLink, AlertTriangle, ChevronRight } from 'lucide-react'
import { getCacheKey, shouldSkipURL } from '../utils/urlUtils.js'



const RISK_COLORS = {
  SAFE:       { color: '#10b981', label: 'Safe',       icon: ShieldCheck },
  LOW:        { color: '#f59e0b', label: 'Low Risk',   icon: Shield },
  SUSPICIOUS: { color: '#f97316', label: 'Suspicious', icon: ShieldAlert },
  DANGEROUS:  { color: '#ef4444', label: 'Dangerous',  icon: ShieldX },
}

function getReasonIcon(reason) {
  if (reason.includes('Google Safe Browsing')) return { icon: Shield, color: '#4285f4' }
  if (reason.includes('IPQualityScore')) return { icon: AlertTriangle, color: '#f59e0b' }
  if (reason.includes('VirusTotal')) return { icon: ShieldAlert, color: '#ef4444' }
  if (reason.includes('typosquatting') || reason.includes('homograph') || reason.includes('internationalized')) {
    return { icon: ShieldX, color: '#f97316' }
  }
  if (reason.includes('redirect')) return { icon: AlertTriangle, color: '#f97316' }
  if (reason.includes('HTTPS')) return { icon: AlertTriangle, color: '#ef4444' }
  if (reason.includes('urgency') || reason.includes('credentials')) return { icon: AlertTriangle, color: '#f59e0b' }
  return { icon: AlertTriangle, color: '#94a3b8' }
}

const WHY_THIS_MATTERS = {
  gsb: "Google maintains a list of sites known to host malware or steal credentials. A match here means this exact URL was already reported by users or automated scanners.",
  ipqs: "This service analyzes domain age, hosting patterns, and known fraud signals. New or disposable domains are commonly used because attackers abandon them quickly once blocked.",
  vt: "Dozens of independent antivirus engines scanned this URL. A high number of detections means multiple security vendors, not just one, agree this is dangerous.",
  lookalike: "Attackers register domains that look almost identical to trusted brands, like 'paypa1.com' instead of 'paypal.com', hoping you won't notice the difference.",
  homograph: "Some letters from other alphabets look identical to Latin letters but are technically different characters. This lets attackers fake a trusted domain name visually.",
  redirect: "Legitimate sites rarely bounce through several unrelated domains. Long redirect chains are often used to hide the final phishing destination from filters.",
  https: "Without HTTPS, any data you submit, including passwords, travels unencrypted and can be intercepted by anyone on the network.",
  urgency: "Phishing pages often create false urgency, telling you to act now or lose access, to make you act before thinking carefully.",
  credentials: "A login form sending your data to a different domain than the one you're visiting is a classic sign of credential theft.",
  headers: "Security headers like CSP and HSTS aren't phishing-specific, but their absence often correlates with quickly built or poorly maintained sites, including phishing pages that skip standard hardening.",
}

function getWhyThisMatters(reason) {
  if (reason.includes('Google Safe Browsing')) return WHY_THIS_MATTERS.gsb
  if (reason.includes('IPQualityScore')) return WHY_THIS_MATTERS.ipqs
  if (reason.includes('VirusTotal')) return WHY_THIS_MATTERS.vt
  if (reason.includes('typosquatting')) return WHY_THIS_MATTERS.lookalike
  if (reason.includes('homograph') || reason.includes('internationalized')) return WHY_THIS_MATTERS.homograph
  if (reason.includes('redirect')) return WHY_THIS_MATTERS.redirect
  if (reason.includes('HTTPS')) return WHY_THIS_MATTERS.https
  if (reason.includes('urgency')) return WHY_THIS_MATTERS.urgency
  if (reason.includes('credentials')) return WHY_THIS_MATTERS.credentials
  if (reason.includes('security header')) return WHY_THIS_MATTERS.headers
  return null
}

function PopupReasonItem({ reason }) {
  const [expanded, setExpanded] = useState(false)
  const { icon: ReasonIcon, color } = getReasonIcon(reason)
  const explanation = getWhyThisMatters(reason)

  return (
    <div>
      <button
        onClick={() => explanation && setExpanded(!expanded)}
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 8,
          background: 'none',
          border: 'none',
          width: '100%',
          textAlign: 'left',
          cursor: explanation ? 'pointer' : 'default',
          padding: 0,
        }}
      >
        <ReasonIcon size={12} color={color} style={{ marginTop: 2, flexShrink: 0 }} />
        <span style={{ fontSize: 12, color: '#f8fafc', lineHeight: 1.5, flex: 1 }}>
          {reason}
        </span>
        {explanation && (
          <ChevronRight size={10} color="#94a3b8" style={{
            marginTop: 3,
            flexShrink: 0,
            transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
            transition: 'transform 0.15s',
          }} />
        )}
      </button>
      {expanded && explanation && (
        <p style={{
          fontSize: 11,
          color: '#94a3b8',
          lineHeight: 1.5,
          marginTop: 4,
          marginLeft: 20,
          paddingLeft: 8,
          borderLeft: '2px solid #2a2d3e',
        }}>
          {explanation}
        </p>
      )}
    </div>
  )
}

function ScoreRing({ score, color }) {
    const [displayScore, setDisplayScore] = useState(0)
    const [phase, setPhase] = useState('sweep-up')
    const radius = 54
    const circumference = 2 * Math.PI * radius

    useEffect(() => {
      let frame
      const sweepUpDuration = 700
      const startTime = performance.now()

      function animate(now) {
        const elapsed = now - startTime
        const progress = Math.min(elapsed / sweepUpDuration, 1)
        setDisplayScore(Math.floor(progress * 100))
        if (progress < 1) {
          frame = requestAnimationFrame(animate)
        } else {
          setPhase('sweep-down')
        }
      }

      frame = requestAnimationFrame(animate)
      return () => cancelAnimationFrame(frame)
    }, [])

    useEffect(() => {
      if (phase !== 'sweep-down') return

      let frame
      const duration = 900
      const startTime = performance.now()
      const startValue = 100

      function animate(now) {
        const elapsed = now - startTime
        const progress = Math.min(elapsed / duration, 1)
        const eased = 1 - Math.pow(1 - progress, 3)
        const current = Math.floor(startValue - (startValue - score) * eased)
        setDisplayScore(current)

        if (progress < 1) {
          frame = requestAnimationFrame(animate)
        } else {
          setDisplayScore(score)
        }
      }

      frame = requestAnimationFrame(animate)
      return () => cancelAnimationFrame(frame)
    }, [phase, score])

    const progress = ((100 - displayScore) / 100) * circumference

    return (
      <div className="flex items-center justify-center my-4">
        <div className="relative" style={{ width: 140, height: 140 }}>
          <svg width="140" height="140" style={{ transform: 'rotate(-90deg)' }}>
            <circle
              cx="70" cy="70" r={radius}
              fill="none"
              stroke="#2a2d3e"
              strokeWidth="10"
            />
            <circle
              cx="70" cy="70" r={radius}
              fill="none"
              stroke={phase === 'sweep-up' ? '#f59e0b' : color}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={progress}
              strokeLinecap="round"
              style={{ transition: phase === 'sweep-down' ? 'stroke 0.3s ease' : 'none' }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span style={{ fontSize: 32, fontWeight: 700, color: phase === 'sweep-up' ? '#f59e0b' : color }}>
              {displayScore}
            </span>
            <span style={{ fontSize: 11, color: '#94a3b8' }}>/ 100</span>
          </div>
        </div>
      </div>
    )
}

function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

function LoadingState() {
  const [dots, setDots] = useState('')

  useEffect(() => {
    const interval = setInterval(() => {
      setDots(d => d.length >= 3 ? '' : d + '.')
    }, 400)
    return () => clearInterval(interval)
  }, [])

 return (
    <div className="flex flex-col items-center justify-center" style={{ minHeight: 300 }}>
      <RefreshCw size={32} color="#f59e0b" className="animate-spin mb-3" />
      <p style={{ color: '#f8fafc', fontSize: 14, fontWeight: 500 }}>
        Analyzing page{dots}
      </p>
      <p style={{ color: '#94a3b8', fontSize: 12, marginTop: 6 }}>
        Checking against threat databases
      </p>
    </div>
  )
}

function NoDataState() {
  return (
    <div className="flex flex-col items-center justify-center gap-3" style={{ minHeight: 300 }}>
      <svg width="64" height="64" viewBox="0 0 64 64" fill="none">
        <circle cx="32" cy="32" r="28" stroke="#2a2d3e" strokeWidth="2" />
        <path d="M32 16 L32 20" stroke="#2a2d3e" strokeWidth="2" strokeLinecap="round" />
        <path d="M20 20 L32 32" stroke="#2a2d3e" strokeWidth="2" strokeLinecap="round" />
        <circle cx="44" cy="44" r="10" fill="#0f1117" stroke="#2a2d3e" strokeWidth="2" />
        <path d="M41 44 L43 46 L47 42" stroke="#94a3b8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
        <path d="M26 36 C26 36 28 40 32 40 C36 40 38 36 38 36" stroke="#2a2d3e" strokeWidth="2" strokeLinecap="round" />
      </svg>
      <p style={{ color: '#f8fafc', fontSize: 14, fontWeight: 500 }}>
        No analysis yet
      </p>
      <p style={{ color: '#94a3b8', fontSize: 12, textAlign: 'center', padding: '0 24px' }}>
        Navigate to a website to see its risk analysis.
      </p>
    </div>
  )
}

export default function Popup() {
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [enabled, setEnabled] = useState(true)
  const [whitelisted, setWhitelisted] = useState(false)


  useEffect(() => {
    chrome.storage.local.get('extensionEnabled').then(({ extensionEnabled }) => {
      setEnabled(extensionEnabled !== false)
    })
  }, [])

  async function handleToggle() {
    const newValue = !enabled
    setEnabled(newValue)
    await chrome.storage.local.set({ extensionEnabled: newValue })

    if (!newValue) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (tab?.id) {
      chrome.tabs.sendMessage(tab.id, { type: 'REMOVE_WARNING' }).catch(() => {})
    }
  }
  }

  

  async function loadResult() {
    setLoading(true)
    try {
      let [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) { setLoading(false); return }

      if (tab.status === 'loading' && (!tab.url || tab.url === 'about:blank')) {
        await new Promise(r => setTimeout(r, 400))
        ;[tab] = await chrome.tabs.query({ active: true, currentWindow: true })
        if (!tab?.id) { setLoading(false); return }
      }

      if (!tab.url || shouldSkipURL(tab.url)) {
        setLoading(false)
        return
      }

      const { whitelist = [] } = await chrome.storage.local.get('whitelist')
      const domain = getCacheKey(tab.url)
      if (whitelist.includes(domain)) {
        setWhitelisted(true)
      }

      const maxAttempts = 30
      let attempts = 0

      const poll = async () => {
        const { extensionEnabled } = await chrome.storage.local.get('extensionEnabled')
        if (extensionEnabled === false) {
          setLoading(false)
          return
        }
        
        const stored = await chrome.storage.local.get(`result_${tab.id}`)
        const data = stored[`result_${tab.id}`]

        const isRecent = data && (Date.now() - data.timestamp < 5 * 60 * 1000)

        if (isRecent) {
          setResult(data)
          setLoading(false)
          return
        }

        attempts++
        if (attempts >= maxAttempts) {
          if (data) {
            setResult(data)
          }
          setLoading(false)
          return
        }

        setTimeout(poll, 500)
      }

      poll()
    } catch (err) {
      console.error('Popup load error:', err)
      setLoading(false)
    }
  }
  
  useEffect(() => {
    let cancelled = false
    let pollInterval = null

    async function init() {
      await loadResult()
    }

    async function pollResult() {
      if (cancelled) return
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) return

      const stored = await chrome.storage.local.get(`result_${tab.id}`)
      const data = stored[`result_${tab.id}`]
      if (data && !cancelled) setResult(data)
    }

    init()
    pollInterval = setInterval(pollResult, 3000)

    return () => {
      cancelled = true
      clearInterval(pollInterval)
    }
  }, [])

  async function handleRescan() {
    setScanning(true)
    setResult(null)
    setLoading(true)
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.id) return

      const rescanStartedAt = Date.now()

      await chrome.runtime.sendMessage({
        type: 'RESCAN',
        tabId: tab.id,
        url: tab.url,
      })

      chrome.tabs.reload(tab.id)

      await waitForFreshResult(tab.id, rescanStartedAt)
    } catch (err) {
      console.error('Rescan error:', err)
      setLoading(false)
    } finally {
      setScanning(false)
    }
  }

  async function waitForFreshResult(tabId, sinceTimestamp) {
    const maxAttempts = 30
    for (let attempts = 0; attempts < maxAttempts; attempts++) {
      const stored = await chrome.storage.local.get(`result_${tabId}`)
      const data = stored[`result_${tabId}`]
      if (data && data.timestamp >= sinceTimestamp) {
        setResult(data)
        setLoading(false)
        return
      }
      await new Promise(r => setTimeout(r, 500))
    }
    setLoading(false)
  }

  async function handleWhitelist() {
    try {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
      if (!tab?.url) return

      const { whitelist = [] } = await chrome.storage.local.get('whitelist')
      const domain = getCacheKey(tab.url)

      if (whitelisted) {

        const updated = whitelist.filter(d => d !== domain)
        await chrome.storage.local.set({ whitelist: updated })
        setWhitelisted(false)
      } else {
        if (!whitelist.includes(domain)) {
          await chrome.storage.local.set({ whitelist: [...whitelist, domain] })
        }
        setWhitelisted(true)
        setTimeout(() => window.close(), 1000)
      }
      
    } catch (err) {
      console.error('Whitelist error:', err)
    }
  }

  function openDashboard() {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/dashboard/dashboard.html') })
  }

  if (loading) return (
    <div style={{ background: '#0f1117', minHeight: 400 }}>
      <Header enabled={enabled} onToggle={handleToggle} />
      <LoadingState />
    </div>
  )

  if (!enabled) return (
    <div style={{ background: '#0f1117', minHeight: 400 }}>
      <Header enabled={enabled} onToggle={handleToggle} />
      <div className="flex flex-col items-center justify-center gap-3" style={{ minHeight: 300 }}>
        <Shield size={40} color="#2a2d3e" />
        <p style={{ color: '#94a3b8', fontSize: 14, textAlign: 'center', padding: '0 24px' }}>
          Linkscope is disabled.
        </p>
        <p style={{ color: '#57534e', fontSize: 12, textAlign: 'center', padding: '0 32px' }}>
          Toggle the switch to re-enable protection.
        </p>
      </div>
      <Footer openDashboard={openDashboard} />
    </div>
  )


  if (!result) return (
    <div style={{ background: '#0f1117', minHeight: 400 }}>
      <Header enabled={enabled} onToggle={handleToggle} />
      <NoDataState />
      <Footer openDashboard={openDashboard} />
    </div>
  )

  

  const riskLabel = result.riskLevel?.label ?? 'SAFE'
  const risk = RISK_COLORS[riskLabel] ?? RISK_COLORS.SAFE
  const RiskIcon = risk.icon

  
  return (
    <div style={{ background: '#0f1117', minHeight: 400 }}>
      <Header enabled={enabled} onToggle={handleToggle} />

      <div style={{ padding: '0 20px' }}>
        <ScoreRing score={result.score ?? 0} color={risk.color} />

        <div className="flex items-center justify-center gap-2 mb-4">
          <RiskIcon size={18} color={risk.color} />
          <span style={{ color: risk.color, fontSize: 16, fontWeight: 600 }}>
            {risk.label}
          </span>
        </div>

        <p style={{
          fontSize: 11,
          color: '#94a3b8',
          textAlign: 'center',
          marginBottom: 16,
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
        }}>
          {result.url}
        </p>

        {result.timestamp && (
          <p style={{ fontSize: 11, color: '#94a3b8', textAlign: 'center', marginBottom: 16 }}>
            Scanned {getTimeAgo(result.timestamp)}
          </p>
        )}

        {result.reasons?.length > 0 && (
          <div style={{
            background: '#1a1d2e',
            border: '1px solid #2a2d3e',
            borderRadius: 10,
            padding: '12px 14px',
            marginBottom: 16,
          }}>
            <p style={{ fontSize: 11, color: '#94a3b8', marginBottom: 8, fontWeight: 500 }}>
              DETECTED THREATS
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {result.reasons.map((reason, i) => (
                <PopupReasonItem key={i} reason={reason} />
              ))}
            </div>
          </div>
        )}


        <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
          <button
            onClick={handleRescan}
            disabled={scanning}
            style={{
              flex: 1,
              padding: '9px 0',
              background: '#1a1d2e',
              border: '1px solid #2a2d3e',
              borderRadius: 8,
              color: '#f8fafc',
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
            }}
          >
            <RefreshCw size={14} className={scanning ? 'animate-spin' : ''} />
            Rescan
          </button>
          <button
            onClick={handleWhitelist}
            style={{
              flex: 1,
              padding: '9px 0',
              background: whitelisted ? '#10b981' : '#1a1d2e',
              border: `1px solid ${whitelisted ? '#10b981' : '#2a2d3e'}`,
              borderRadius: 8,
              color: '#f8fafc',
              fontSize: 13,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: 6,
              transition: 'background 0.2s, border 0.2s',
            }}
          >
            <ShieldCheck size={14} />
            {whitelisted ? 'Unwhitelist' : 'Whitelist'}
          </button>
        </div>
      </div>

      <Footer openDashboard={openDashboard} />
    </div>
  )
}

function Header({ enabled, onToggle }) {
  return (
    <div style={{
      padding: '16px 20px',
      borderBottom: '1px solid #2a2d3e',
      display: 'flex',
      alignItems: 'center',
      gap: 10,
    }}>
      <Shield size={20} color="#f59e0b" />
      <span style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', flex: 1 }}>
        Linkscope
      </span>

      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginRight: 8 }}>
        <div style={{ position: 'relative', width: 8, height: 8 }}>
          <div style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            background: enabled ? '#10b981' : '#94a3b8',
            opacity: 0.4,
            animation: enabled ? 'pulse 2s infinite' : 'none',
            transform: 'scale(1)',
          }} />
          <div style={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            background: enabled ? '#10b981' : '#94a3b8',
          }} />
        </div>
        <span style={{ fontSize: 11, color: enabled ? '#10b981' : '#94a3b8' }}>
          {enabled ? 'Active' : 'Disabled'}
        </span>
      </div>

      <button
        onClick={onToggle}
        style={{
          width: 40,
          height: 22,
          borderRadius: 11,
          border: 'none',
          background: enabled ? '#f59e0b' : '#2a2d3e',
          cursor: 'pointer',
          position: 'relative',
          transition: 'background 0.2s',
          flexShrink: 0,
        }}
      >
        <span style={{
          position: 'absolute',
          top: 3,
          left: enabled ? 21 : 3,
          width: 16,
          height: 16,
          borderRadius: '50%',
          background: '#f8fafc',
          transition: 'left 0.2s',
        }} />
      </button>
    </div>
  )
}

function Footer({ openDashboard }) {
  return (
    <div style={{
      padding: '12px 20px',
      borderTop: '1px solid #2a2d3e',
      display: 'flex',
      justifyContent: 'center',
    }}>
      <button
        onClick={openDashboard}
        style={{
          background: 'none',
          border: 'none',
          color: '#94a3b8',
          fontSize: 12,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          gap: 5,
        }}
      >
        <ExternalLink size={12} />
        Open Dashboard
      </button>
    </div>
  )
}