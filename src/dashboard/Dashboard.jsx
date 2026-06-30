/* global chrome */

import { useEffect, useState } from 'react'
import { Shield, ShieldCheck, ShieldAlert, ShieldX, History, Settings, BarChart3, Trash2, ChevronRight, X, AlertTriangle, ExternalLink } from 'lucide-react'

const RISK_COLORS = {
  SAFE:       { color: '#10b981', label: 'Safe',       icon: ShieldCheck },
  LOW:        { color: '#f59e0b', label: 'Low Risk',   icon: Shield },
  SUSPICIOUS: { color: '#f97316', label: 'Suspicious', icon: ShieldAlert },
  DANGEROUS:  { color: '#ef4444', label: 'Dangerous',  icon: ShieldX },
}

function getFaviconUrl(url) {
  try {
    const domain = new URL(url).hostname
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`
  } catch {
    return null
  }
}

function getTimeAgo(timestamp) {
  const seconds = Math.floor((Date.now() - timestamp) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
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

function ReasonItem({ reason }) {
  const [expanded, setExpanded] = useState(false)
  const { icon: ReasonIcon, color } = getReasonIcon(reason)
  const explanation = getWhyThisMatters(reason)

  return (
    <div style={{ marginBottom: 4 }}>
      <button
        onClick={() => explanation && setExpanded(!expanded)}
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 10,
          background: 'none',
          border: 'none',
          width: '100%',
          textAlign: 'left',
          cursor: explanation ? 'pointer' : 'default',
          padding: 0,
        }}
      >
        <ReasonIcon size={14} color={color} style={{ marginTop: 2, flexShrink: 0 }} />
        <p style={{ fontSize: 13, color: '#f8fafc', lineHeight: 1.5, flex: 1 }}>
          {reason}
        </p>
        {explanation && (
          <ChevronRight size={14} color="#94a3b8" style={{
            marginTop: 3,
            transform: expanded ? 'rotate(90deg)' : 'rotate(0deg)',
            transition: 'transform 0.15s',
            flexShrink: 0,
          }} />
        )}
      </button>
      {expanded && explanation && (
        <p style={{
          fontSize: 12,
          color: '#94a3b8',
          lineHeight: 1.5,
          marginTop: 6,
          marginLeft: 24,
          paddingLeft: 10,
          borderLeft: '2px solid #2a2d3e',
        }}>
          {explanation}
        </p>
      )}
    </div>
  )
}

function generatePrintableReport(entry) {
  const risk = getRiskFromScore(entry.score)
  const reasonsHtml = entry.reasons?.length > 0
    ? entry.reasons.map(r => `<li>${r}</li>`).join('')
    : ''

  const summaryLine = entry.score === 0
    ? 'This site shows no significant risk indicators at the time of scanning.'
    : entry.score <= 20
    ? 'This site shows minimal risk indicators.'
    : `This site was flagged with ${entry.reasons?.length || 0} risk indicator${entry.reasons?.length !== 1 ? 's' : ''}.`

  const headersHtml = entry.securityHeaders ? `
    <table class="headers-table">
      <tr><td>Content-Security-Policy</td><td class="${entry.securityHeaders.hasCSP ? 'present' : 'missing'}">${entry.securityHeaders.hasCSP ? 'Present' : 'Missing'}</td></tr>
      <tr><td>Strict-Transport-Security</td><td class="${entry.securityHeaders.hasHSTS ? 'present' : 'missing'}">${entry.securityHeaders.hasHSTS ? 'Present' : 'Missing'}</td></tr>
      <tr><td>X-Frame-Options</td><td class="${entry.securityHeaders.hasXFrameOptions ? 'present' : 'missing'}">${entry.securityHeaders.hasXFrameOptions ? 'Present' : 'Missing'}</td></tr>
      <tr><td>X-Content-Type-Options</td><td class="${entry.securityHeaders.hasXContentTypeOptions ? 'present' : 'missing'}">${entry.securityHeaders.hasXContentTypeOptions ? 'Present' : 'Missing'}</td></tr>
    </table>
  ` : ''

  const cleanUrlForTitle = entry.url.replace(/^https?:\/\//, '').replace(/\/$/, '')
  const faviconUrl = getFaviconUrl(entry.url)

  const printWindow = window.open('', '_blank')
  printWindow.document.write(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Linkscope Report - ${cleanUrlForTitle}</title>
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          color: #0f1117;
          padding: 48px;
          max-width: 720px;
          margin: 0 auto;
        }
        .header {
          display: flex;
          align-items: center;
          gap: 12px;
          border-bottom: 3px solid #f59e0b;
          padding-bottom: 20px;
          margin-bottom: 32px;
        }
        .logo-badge {
          width: 36px; height: 36px;
          background: #0f1117;
          border-radius: 8px;
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;
        }
        .header h1 { font-size: 22px; font-weight: 700; }
        .header p { font-size: 12px; color: #57534e; margin-top: 4px; }
        .section { margin-bottom: 28px; }
        .section-label {
          font-size: 11px;
          font-weight: 600;
          color: #78716c;
          letter-spacing: 0.05em;
          margin-bottom: 8px;
          text-transform: uppercase;
        }
        .url-box {
          background: #f5f5f4;
          border-radius: 8px;
          padding: 14px 16px;
          font-size: 13px;
          word-break: break-all;
          display: flex;
          align-items: center;
          gap: 10px;
        }
        .score-row {
          display: flex;
          align-items: center;
          gap: 20px;
          margin-bottom: 8px;
        }
        .score-badge {
          font-size: 36px;
          font-weight: 700;
          color: ${risk.color};
        }
        .risk-label {
          font-size: 16px;
          font-weight: 700;
          color: ${risk.color};
        }
        .summary {
          font-size: 13px;
          color: #44403c;
          margin-top: 8px;
        }
        ul { padding-left: 18px; }
        li { font-size: 13px; margin-bottom: 8px; line-height: 1.5; }
        .no-threats { font-size: 13px; color: #78716c; }
        .headers-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .headers-table td { padding: 8px 0; border-bottom: 1px solid #e7e5e4; }
        .headers-table td:last-child { text-align: right; font-weight: 600; }
        .present { color: #059669; }
        .missing { color: #78716c; }
        .footer {
          margin-top: 40px;
          padding-top: 16px;
          border-top: 1px solid #e7e5e4;
          font-size: 11px;
          color: #a8a29e;
        }
        @media print {
          body { padding: 24px; }
        }
      </style>
    </head>
    <body>
      <div class="header">
        <div>
          <h1>Linkscope Security Report</h1>
          <p>Generated ${new Date().toLocaleString()}</p>
        </div>
      </div>

      <div class="section">
        <p class="section-label">Target URL</p>
        <div class="url-box">
          ${faviconUrl ? `<img src="${faviconUrl}" width="16" height="16" style="border-radius:3px;flex-shrink:0;" />` : ''}
          <span>${entry.url}</span>
        </div>
      </div>

      <div class="section">
        <p class="section-label">Risk Assessment</p>
        <div class="score-row">
          <span class="score-badge">${entry.score}/100</span>
          <span class="risk-label">${risk.label}</span>
        </div>
        <p class="summary">${summaryLine}</p>
      </div>

      <div class="section">
        <p class="section-label">Detected Threats</p>
        ${reasonsHtml ? `<ul>${reasonsHtml}</ul>` : '<p class="no-threats">No specific threats identified.</p>'}
      </div>

      ${entry.securityHeaders ? `
      <div class="section">
        <p class="section-label">Security Headers</p>
        ${headersHtml}
      </div>
      ` : ''}

      <div class="section">
        <p class="section-label">Scan Metadata</p>
        <p style="font-size: 13px;">Scanned: ${new Date(entry.timestamp).toLocaleString()}</p>
        ${entry.dataFetchedAt && Math.abs(entry.timestamp - entry.dataFetchedAt) > 60000 ? `<p style="font-size: 12px; color: #78716c; margin-top: 4px;">Threat data last refreshed: ${new Date(entry.dataFetchedAt).toLocaleString()}</p>` : ''}
      </div>

      <div class="footer">
        Generated by Linkscope - Real-time phishing and threat detection
      </div>
    </body>
    </html>
  `)
  printWindow.document.close()
  printWindow.focus()
  setTimeout(() => printWindow.print(), 250)
}

function getRiskFromScore(score) {
  if (score <= 20) return RISK_COLORS.SAFE
  if (score <= 40) return RISK_COLORS.LOW
  if (score <= 70) return RISK_COLORS.SUSPICIOUS
  return RISK_COLORS.DANGEROUS
}

function Sidebar({ page, setPage, collapsed, setCollapsed }) {
  const items = [
    { id: 'overview', label: 'Overview', icon: BarChart3 },
    { id: 'history',  label: 'History',  icon: History   },
    { id: 'settings', label: 'Settings', icon: Settings  },
  ]

  return (
    <div style={{
      width: collapsed ? 64 : 220,
      minHeight: '100vh',
      height: '100vh',
      position: 'sticky',
      top: 0,
      background: '#1a1d2e',
      borderRight: '1px solid #2a2d3e',
      display: 'flex',
      flexDirection: 'column',
      padding: '24px 0',
      flexShrink: 0,
      transition: 'width 0.2s ease',
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        padding: collapsed ? '0 0 0 21px' : '0 20px',
        marginBottom: 32,
        overflow: 'hidden',
      }}>
        <Shield size={22} color="#f59e0b" style={{ flexShrink: 0 }} />
        {!collapsed && (
          <span style={{
            fontSize: 15,
            fontWeight: 700,
            color: '#f8fafc',
            whiteSpace: 'nowrap',
          }}>
            Linkscope
          </span>
        )}
      </div>

      {items.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          onClick={() => setPage(id)}
          onMouseEnter={e => { if (page !== id) e.currentTarget.style.color = '#f8fafc' }}
          onMouseLeave={e => { if (page !== id) e.currentTarget.style.color = '#94a3b8' }}
          title={collapsed ? label : undefined}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            padding: collapsed ? '10px 0 10px 21px' : '10px 20px',
            background: page === id ? '#0f1117' : 'none',
            border: 'none',
            borderLeft: page === id ? '2px solid #f59e0b' : '2px solid transparent',
            color: page === id ? '#f8fafc' : '#94a3b8',
            fontSize: 14,
            cursor: 'pointer',
            textAlign: 'left',
            width: '100%',
            transition: 'color 0.15s',
            overflow: 'hidden',
          }}
        >
          <Icon size={16} style={{ flexShrink: 0 }} />
          {!collapsed && <span style={{ whiteSpace: 'nowrap' }}>{label}</span>}
        </button>
      ))}

      <div style={{ flex: 1 }} />

      <button
        onClick={() => setCollapsed(!collapsed)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: collapsed ? '10px 0 10px 21px' : '10px 20px',
          background: 'none',
          border: 'none',
          color: '#94a3b8',
          fontSize: 13,
          cursor: 'pointer',
          textAlign: 'left',
          width: '100%',
        }}
        onMouseEnter={e => e.currentTarget.style.color = '#f8fafc'}
        onMouseLeave={e => e.currentTarget.style.color = '#94a3b8'}
      >
        <ChevronRight
          size={16}
          style={{
            flexShrink: 0,
            transform: collapsed ? 'rotate(0deg)' : 'rotate(180deg)',
            transition: 'transform 0.2s',
          }}
        />
        {!collapsed && <span>Collapse</span>}
      </button>
    </div>
  )
}


function ThreatBreakdownBar({ history }) {
  const total = history.length
  if (total === 0) return null

  const safe       = history.filter(h => h.score <= 20).length
  const low        = history.filter(h => h.score > 20 && h.score <= 40).length
  const suspicious = history.filter(h => h.score > 40 && h.score <= 70).length
  const dangerous  = history.filter(h => h.score > 70).length

  const segments = [
    { count: safe,       color: '#10b981', label: 'Safe'       },
    { count: low,        color: '#f59e0b', label: 'Low'        },
    { count: suspicious, color: '#f97316', label: 'Suspicious' },
    { count: dangerous,  color: '#ef4444', label: 'Dangerous'  },
  ].filter(s => s.count > 0)

  return (
    <div style={{
      background: '#1a1d2e',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: '20px 24px',
      marginBottom: 32,
    }}>
      <p style={{ fontSize: 12, color: '#94a3b8', fontWeight: 500, letterSpacing: '0.05em', marginBottom: 14 }}>
        RISK DISTRIBUTION
      </p>

      {/* Stacked bar */}
      <div style={{
        display: 'flex',
        height: 8,
        borderRadius: 4,
        overflow: 'hidden',
        gap: 2,
        marginBottom: 12,
      }}>
        {segments.map(({ count, color, label }) => (
          <div
            key={label}
            style={{
              flex: count,
              background: color,
              borderRadius: 4,
              transition: 'flex 0.5s ease',
            }}
          />
        ))}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 16 }}>
        {segments.map(({ count, color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: '50%', background: color }} />
            <span style={{ fontSize: 12, color: '#94a3b8' }}>
              {label} <span style={{ color: '#f8fafc', fontWeight: 600 }}>{count}</span>
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}


function getSeverityRowStyle(score) {
  if (score > 70) return { background: 'rgba(239,68,68,0.06)' }
  if (score > 40) return { background: 'rgba(249,115,22,0.05)' }
  if (score > 20) return { background: 'rgba(245,158,11,0.04)' }
  return { }
}

function WeeklyTrendChart({ history }) {
  const days = []
  for (let i = 6; i >= 0; i--) {
    const date = new Date()
    date.setDate(date.getDate() - i)
    date.setHours(0, 0, 0, 0)
    days.push(date)
  }

  const counts = days.map(day => {
    const nextDay = new Date(day)
    nextDay.setDate(nextDay.getDate() + 1)
    return history.filter(h => h.timestamp >= day.getTime() && h.timestamp < nextDay.getTime()).length
  })

  const max = Math.max(...counts, 1)
  const weekTotal = counts.reduce((a, b) => a + b, 0)

  return (
    <div style={{
      background: '#1a1d2e',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: '20px 24px',
      marginBottom: 24,
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 20 }}>
        <p style={{ fontSize: 12, color: '#94a3b8', fontWeight: 500, letterSpacing: '0.05em' }}>
          SCANS - LAST 7 DAYS
        </p>
        <p style={{ fontSize: 12, color: '#f8fafc', fontWeight: 600 }}>
          {weekTotal} total
        </p>
      </div>
      <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, height: 90, padding: '0 4px' }}>
        {days.map((day, i) => {
          const isToday = i === 6
          return (
            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
              <span style={{
                fontSize: 11,
                fontWeight: 600,
                color: counts[i] > 0 ? '#f8fafc' : '#57534e',
                minHeight: 14,
              }}>
                {counts[i] > 0 ? counts[i] : ''}
              </span>
              <div style={{
                width: '60%',
                height: Math.max((counts[i] / max) * 50, counts[i] > 0 ? 4 : 2),
                background: isToday ? '#f59e0b' : counts[i] > 0 ? 'rgba(245,158,11,0.5)' : '#2a2d3e',
                borderRadius: 3,
                transition: 'height 0.4s ease',
              }} />
              <span style={{ fontSize: 10, color: isToday ? '#f59e0b' : '#94a3b8', fontWeight: isToday ? 600 : 400 }}>
                {day.toLocaleDateString(undefined, { weekday: 'short' }).slice(0, 2)}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function TopDomainsCard({ history }) {
  const domainStats = {}

  history.forEach(h => {
    let domain
    try { domain = new URL(h.url).hostname } catch { return }
    if (!domainStats[domain]) {
      domainStats[domain] = { domain, count: 0, maxScore: 0, url: h.url }
    }
    domainStats[domain].count += 1
    domainStats[domain].maxScore = Math.max(domainStats[domain].maxScore, h.score)
  })

  const topDomains = Object.values(domainStats)
    .sort((a, b) => b.count - a.count)
    .slice(0, 5)

  return (
    <div style={{
      background: '#1a1d2e',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: '20px 24px',
      marginBottom: 24,
    }}>
      <p style={{ fontSize: 12, color: '#94a3b8', fontWeight: 500, letterSpacing: '0.05em', marginBottom: 16 }}>
        MOST VISITED DOMAINS
      </p>
      {topDomains.length === 0 ? (
        <p style={{ fontSize: 13, color: '#94a3b8' }}>No data yet.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {topDomains.map(({ domain, count, maxScore, url }) => {
            const risk = getRiskFromScore(maxScore)
            return (
              <div key={domain} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <img
                  src={getFaviconUrl(url)}
                  alt=""
                  width={16}
                  height={16}
                  style={{ borderRadius: 3, flexShrink: 0 }}
                  onError={e => { e.target.style.display = 'none' }}
                />
                <span style={{
                  flex: 1,
                  fontSize: 13,
                  color: '#f8fafc',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {domain}
                </span>
                <span style={{ fontSize: 11, color: risk.color, fontWeight: 600 }}>
                  {maxScore}
                </span>
                <span style={{ fontSize: 11, color: '#94a3b8', minWidth: 50, textAlign: 'right' }}>
                  {count} visit{count !== 1 ? 's' : ''}
                </span>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

function ProtectionSummary({ history }) {

  // eslint-disable-next-line react-hooks/purity -- one-week cutoff doesn't need per-render precision
  const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000
  
  const thisWeek = history.filter(h => h.timestamp >= oneWeekAgo)

  const sitesProtected = thisWeek.length
  const threatsBlocked = thisWeek.filter(h => h.score > 40).length
  const uniqueDomains = new Set(thisWeek.map(h => {
    try { return new URL(h.url).hostname } catch { return h.url }
  })).size

  if (sitesProtected === 0) {
    return (
      <div style={{
        background: 'linear-gradient(135deg, rgba(245,158,11,0.08), rgba(245,158,11,0.02))',
        border: '1px solid #2a2d3e',
        borderRadius: 12,
        padding: '24px 28px',
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        gap: 16,
      }}>
        <Shield size={28} color="#f59e0b" style={{ flexShrink: 0 }} />
        <p style={{ fontSize: 14, color: '#94a3b8', margin: 0 }}>
          No activity yet this week. Once you start browsing, your protection summary will appear here.
        </p>
      </div>
    )
  }

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(245,158,11,0.08), rgba(245,158,11,0.02))',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: '24px 28px',
      marginBottom: 24,
      display: 'flex',
      alignItems: 'center',
      gap: 16,
    }}>
      <Shield size={28} color="#f59e0b" style={{ flexShrink: 0 }} />
      <p style={{ fontSize: 15, color: '#f8fafc', margin: 0, lineHeight: 1.6 }}>
        This week, Linkscope checked <strong style={{ color: '#f59e0b' }}>{sitesProtected} site{sitesProtected !== 1 ? 's' : ''}</strong>
        {' '}across <strong style={{ color: '#f59e0b' }}>{uniqueDomains} domain{uniqueDomains !== 1 ? 's' : ''}</strong>.
        {threatsBlocked > 0 ? (
          <> <strong style={{ color: '#ef4444' }}>{threatsBlocked} threat{threatsBlocked !== 1 ? 's' : ''}</strong> were flagged before you could be exposed to them.</>
        ) : (
          ' No threats were detected — your browsing stayed clean.'
        )}
      </p>
    </div>
  )
}

function OverviewPage({ history, setDetailEntry, setPage }) {
  const total = history.length
  const threats = history.filter(h => h.score > 20).length
  const dangerous = history.filter(h => h.score > 70).length
  const safe = history.filter(h => h.score <= 20).length

  const stats = [
    { label: 'Total Scans',      value: total,     color: '#f8fafc' },
    { label: 'Safe Sites',       value: safe,      color: '#10b981' },
    { label: 'Threats Detected', value: threats,   color: '#f59e0b' },
    { label: 'Dangerous Sites',  value: dangerous, color: '#ef4444' },
  ]

  const recent = history.slice(0, 5)

  return (
    <div style={{ padding: 32 }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f8fafc', marginBottom: 8 }}>
        Overview
      </h1>
      <p style={{ fontSize: 14, color: '#94a3b8', marginBottom: 32 }}>
        Summary of your browsing protection activity.
      </p>

      <ProtectionSummary history={history} />
      <ThreatBreakdownBar history={history} />

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 8 }}>
        <WeeklyTrendChart history={history} />
        <TopDomainsCard history={history} />
      </div>  

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(4, 1fr)',
        gap: 16,
        marginBottom: 40,
      }}>
        {stats.map(({ label, value, color }) => (
          <div key={label} style={{
            background: '#1a1d2e',
            border: '1px solid #2a2d3e',
            borderRadius: 12,
            padding: '24px',
            position: 'relative',
            overflow: 'hidden',
          }}>
            <div style={{
              position: 'absolute',
              top: 0, right: 0,
              width: 80, height: 80,
              borderRadius: '0 12px 0 80px',
              background: color,
              opacity: 0.08,
            }} />
            <p style={{
              fontSize: 12,
              color: '#94a3b8',
              marginBottom: 12,
              fontWeight: 500,
              letterSpacing: '0.05em',
            }}>
              {label.toUpperCase()}
            </p>
            <p style={{ fontSize: 36, fontWeight: 700, color, lineHeight: 1 }}>
              {value}
            </p>
          </div>
        ))}
      </div>

      <h2 style={{ fontSize: 16, fontWeight: 600, color: '#f8fafc', marginBottom: 16 }}>
        Recent Activity
      </h2>
      {recent.length === 0 ? (
        <p style={{ color: '#94a3b8', fontSize: 14 }}>No scans yet.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {recent.map((entry, i) => {
            const risk = getRiskFromScore(entry.score)
            return (
              <button
                key={i}
                onClick={() => {
                  setDetailEntry(entry)
                  setPage('detail')
                }}
                style={{
                  background: '#1a1d2e', border: '1px solid #2a2d3e', borderRadius: 10,
                  padding: '12px 16px', display: 'flex', alignItems: 'center',
                  gap: 12, width: '100%', textAlign: 'left', cursor: 'pointer',
                  transition: 'border-color 0.15s',
                  ...getSeverityRowStyle(entry.score),
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = '#f59e0b'}
                onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d3e'}
              >
                <div style={{ position: 'relative', width: 20, height: 20, flexShrink: 0 }}>
                  <img
                    src={getFaviconUrl(entry.url)}
                    alt=""
                    width={20}
                    height={20}
                    style={{ borderRadius: 4 }}
                    onError={e => { e.target.style.display = 'none' }}
                  />
                  <div style={{
                    position: 'absolute',
                    bottom: -2,
                    right: -2,
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: risk.color,
                    border: '1.5px solid #1a1d2e',
                  }} />
                </div>
                <span style={{
                  flex: 1,
                  fontSize: 13,
                  color: '#f8fafc',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {entry.url}
                </span>
                <span style={{ fontSize: 12, color: risk.color, fontWeight: 600 }}>
                  {entry.score}
                </span>
                <span style={{ fontSize: 11, color: '#94a3b8' }}>
                  {getTimeAgo(entry.timestamp)}
                </span>
            </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

function HistoryPage({ history, setHistory, setDetailEntry, setPage }) {
  const [filter, setFilter] = useState('ALL')
  const [search, setSearch] = useState('')

  const filters = ['ALL', 'SAFE', 'LOW', 'SUSPICIOUS', 'DANGEROUS']

  const filtered = history .filter(h => {
      if (filter === 'SAFE')       return h.score <= 20
      if (filter === 'LOW')        return h.score > 20 && h.score <= 40
      if (filter === 'SUSPICIOUS') return h.score > 40 && h.score <= 70
      if (filter === 'DANGEROUS')  return h.score > 70
      return true
    })
    .filter(h => h.url.toLowerCase().includes(search.toLowerCase()))

  async function clearHistory() {
    await chrome.storage.local.set({ scanHistory: [] })
    setHistory([])
  }

  function exportHistory(history) {
    const csv = [
      'URL,Score,Risk Level,Timestamp,Reasons',
      ...history.map(h =>
        `"${h.url}",${h.score},"${h.riskLevel}","${new Date(h.timestamp).toLocaleString()}","${h.reasons.join(' | ')}"`
      )
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `phishing-detector-history-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ flex: 1 }}>
          <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>
            Scan History
          </h1>
          <p style={{ fontSize: 14, color: '#94a3b8' }}>
            {history.length} sites scanned
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={() => exportHistory(history)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '8px 14px',
              background: 'none',
              border: '1px solid #2a2d3e',
              borderRadius: 8,
              color: '#94a3b8',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            <ExternalLink size={14} />
            Export CSV
          </button>
          <button
            onClick={clearHistory}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '8px 14px',
              background: 'none',
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: 8,
              color: '#ef4444',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            <Trash2 size={14} />
            Clear History
          </button>
        </div>
      </div>

      <input
        type="text"
        placeholder="Search by URL..."
        value={search}
        onChange={e => setSearch(e.target.value)}
        style={{
          width: '100%',
          padding: '10px 14px',
          background: '#1a1d2e',
          border: '1px solid #2a2d3e',
          borderRadius: 8,
          color: '#f8fafc',
          fontSize: 13,
          marginTop: 20,
          marginBottom: 16,
          outline: 'none',
        }}
      />

      <div style={{ display: 'flex', gap: 8, marginBottom: 20, marginTop: 20 }}>
        {filters.map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '5px 12px',
              borderRadius: 6,
              border: '1px solid',
              borderColor: filter === f ? '#f59e0b' : '#2a2d3e',
              background: filter === f ? 'rgba(245,158,11,0.1)' : 'none',
              color: filter === f ? '#f59e0b' : '#94a3b8',
              fontSize: 12,
              cursor: 'pointer',
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p style={{ color: '#94a3b8', fontSize: 14 }}>No entries found.</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {filtered.map((entry, i) => {
            const risk = getRiskFromScore(entry.score)
            return (
              <button
                key={i}
                onClick={() => {
                  setDetailEntry(entry)
                  setPage('detail')
                }}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '12px 16px',
                  background: '#1a1d2e',
                  border: '1px solid #2a2d3e',
                  borderRadius: 10,
                  cursor: 'pointer',
                  textAlign: 'left',
                  width: '100%',
                  transition: 'border-color 0.15s',
                  ...getSeverityRowStyle(entry.score),
                }}
                onMouseEnter={e => e.currentTarget.style.borderColor = '#f59e0b'}
                onMouseLeave={e => e.currentTarget.style.borderColor = '#2a2d3e'}
              >
                <div style={{ position: 'relative', width: 20, height: 20, flexShrink: 0 }}>
                  <img
                    src={getFaviconUrl(entry.url)}
                    alt=""
                    width={20}
                    height={20}
                    style={{ borderRadius: 4 }}
                    onError={e => { e.target.style.display = 'none' }}
                  />
                  <div style={{
                    position: 'absolute',
                    bottom: -2,
                    right: -2,
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: risk.color,
                    border: '1.5px solid #1a1d2e',
                  }} />
                </div>
                <span style={{
                  flex: 1,
                  fontSize: 13,
                  color: '#f8fafc',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {entry.url}
                </span>
                <span style={{
                  fontSize: 12,
                  color: risk.color,
                  fontWeight: 600,
                  minWidth: 24,
                  textAlign: 'right',
                }}>
                  {entry.score}
                </span>
                <span style={{ fontSize: 11, color: '#94a3b8', minWidth: 60, textAlign: 'right' }}>
                  {getTimeAgo(entry.timestamp)}
                </span>
                <ChevronRight size={14} color="#94a3b8" />
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
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


function DetailPage({ entry, setPage }) {
  if (!entry) return null
  const risk = getRiskFromScore(entry.score)
  const RiskIcon = risk.icon

  return (
    <div style={{ padding: 32 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <button
          onClick={() => setPage('history')}
          style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none', border: 'none', color: '#94a3b8', fontSize: 13, cursor: 'pointer', padding: 0, flexShrink: 0 }}
        >
          ← Back to History
        </button>
        <button
          onClick={() => generatePrintableReport(entry)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 6,
            padding: '7px 14px',
            background: '#1a1d2e',
            border: '1px solid #2a2d3e',
            borderRadius: 8,
            color: '#f8fafc',
            fontSize: 13,
            cursor: 'pointer',
            flexShrink: 0,
          }}
        >
          <ExternalLink size={14} />
          Download Report
        </button>
      </div>

      <div style={{
        background: '#1a1d2e',
        border: `1px solid ${risk.color}`,
        borderRadius: 12,
        padding: 24,
        marginBottom: 20,
        maxWidth: 720,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
          <RiskIcon size={24} color={risk.color} />
          <div>
            <p style={{ fontSize: 18, fontWeight: 700, color: risk.color }}>
              {risk.label}
            </p>
            <p style={{ fontSize: 12, color: '#94a3b8' }}>
              Risk Score: {entry.score}/100
            </p>
          </div>
        </div>

        <div style={{
          background: '#0f1117',
          borderRadius: 8,
          padding: '10px 14px',
          marginBottom: 16,
          display: 'flex',
          alignItems: 'center',
          gap: 10,
        }}>
          <img
            src={getFaviconUrl(entry.url)}
            alt=""
            width={20}
            height={20}
            style={{ borderRadius: 4, flexShrink: 0 }}
            onError={e => { e.target.style.display = 'none' }}
          />
          <div style={{ flex: 1 }}>
          <p style={{ fontSize: 12, color: '#94a3b8', marginBottom: 4 }}>URL</p>
          <p style={{ fontSize: 13, color: '#f8fafc', wordBreak: 'break-all' }}>
            {entry.url}
          </p>
          </div>
        </div>

        <p style={{ fontSize: 11, color: '#94a3b8' }}>
          Scanned {getTimeAgo(entry.timestamp)} - {new Date(entry.timestamp).toLocaleString()}
        </p>
        {entry.dataFetchedAt && Math.abs(entry.timestamp - entry.dataFetchedAt) > 60000 && (
          <p style={{ fontSize: 11, color: '#94a3b8', marginTop: 4 }}>
            Threat data cached from {getTimeAgo(entry.dataFetchedAt)}
          </p>
        )}
      </div>

      {entry.reasons?.length > 0 && (
        <div style={{
          background: '#1a1d2e',
          border: '1px solid #2a2d3e',
          borderRadius: 12,
          padding: 24,
          maxWidth: 720,
        }}>
          <p style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>
            DETECTED THREATS
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {entry.reasons.map((reason, i) => (
              <ReasonItem key={i} reason={reason} />
            ))}
            
          </div>
        </div>
      )}
      {entry.securityHeaders && (
          <div style={{ background: '#1a1d2e', border: '1px solid #2a2d3e', borderRadius: 12, padding: 24, marginTop: 20, maxWidth: 720, }}>
              <p style={{ fontSize: 13, fontWeight: 600, color: '#94a3b8', marginBottom: 16 }}>
                SECURITY HEADERS
              </p>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[
                  { label: 'Content-Security-Policy', present: entry.securityHeaders.hasCSP },
                  { label: 'Strict-Transport-Security', present: entry.securityHeaders.hasHSTS },
                  { label: 'X-Frame-Options', present: entry.securityHeaders.hasXFrameOptions },
                  { label: 'X-Content-Type-Options', present: entry.securityHeaders.hasXContentTypeOptions },
                ].map(({ label, present }) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 13, color: '#f8fafc' }}>{label}</span>
                    <span style={{ fontSize: 12, fontWeight: 600, color: present ? '#10b981' : '#94a3b8', display: 'flex', alignItems: 'center', gap: 4, }}>
                      {present ? <ShieldCheck size={13} /> : <X size={13} />}
                      {present ? 'Present' : 'Missing'}
                    </span>
                  </div>
                ))}
              </div>
          </div>
      )}
    </div>
  )
}

function ThresholdSettings() {
  const [thresholds, setThresholds] = useState({ low: 20, suspicious: 40, dangerous: 70 })
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    chrome.storage.local.get('riskThresholds').then(({ riskThresholds }) => {
      if (riskThresholds) setThresholds(riskThresholds)
    })
  }, [])

  async function handleSave() {
    await chrome.storage.local.set({ riskThresholds: thresholds })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  function handleReset() {
    setThresholds({ low: 20, suspicious: 40, dangerous: 70 })
  }

  const sliderRow = (label, key, color) => (
    <div key={key} style={{ marginBottom: 16 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ fontSize: 13, color: '#f8fafc' }}>{label}</span>
        <span style={{ fontSize: 13, color, fontWeight: 600 }}>{thresholds[key]}</span>
      </div>
      <input
        type="range"
        min={1}
        max={99}
        value={thresholds[key]}
        onChange={e => setThresholds(prev => ({ ...prev, [key]: Number(e.target.value) }))}
        style={{ width: '100%', accentColor: color }}
      />
    </div>
  )

  return (
    <div style={{
      background: '#1a1d2e',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: 24,
      marginBottom: 24,
    }}>
      <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', marginBottom: 4 }}>
        Risk Thresholds
      </h2>
      <p style={{ fontSize: 12, color: '#94a3b8', marginBottom: 20 }}>
        Adjust the score boundaries used to classify risk level.
      </p>

      {sliderRow('Low risk above', 'low', '#f59e0b')}
      {sliderRow('Suspicious above', 'suspicious', '#f97316')}
      {sliderRow('Dangerous above', 'dangerous', '#ef4444')}

      <div style={{ display: 'flex', gap: 8, marginTop: 20 }}>
        <button
          onClick={handleSave}
          style={{
            flex: 1,
            padding: '10px 0',
            background: saved ? '#10b981' : '#f59e0b',
            border: 'none',
            borderRadius: 8,
            color: '#0f1117',
            fontSize: 14,
            fontWeight: 600,
            cursor: 'pointer',
          }}
        >
          {saved ? 'Saved' : 'Save Thresholds'}
        </button>
        <button
          onClick={handleReset}
          style={{
            padding: '10px 16px',
            background: 'none',
            border: '1px solid #2a2d3e',
            borderRadius: 8,
            color: '#94a3b8',
            fontSize: 13,
            cursor: 'pointer',
          }}
        >
          Reset
        </button>
      </div>
    </div>
  )
}

function NotificationSettings() {
  const [enabled, setEnabled] = useState(true)

  useEffect(() => {
    chrome.storage.local.get('notificationsEnabled').then(({ notificationsEnabled }) => {
      setEnabled(notificationsEnabled !== false)
    })
  }, [])

  async function handleToggle() {
    const newValue = !enabled
    setEnabled(newValue)
    await chrome.storage.local.set({ notificationsEnabled: newValue })
  }

  return (
    <div style={{
      background: '#1a1d2e',
      border: '1px solid #2a2d3e',
      borderRadius: 12,
      padding: 24,
      marginBottom: 24,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
    }}>
      <div>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', marginBottom: 4 }}>
          Desktop Notifications
        </h2>
        <p style={{ fontSize: 12, color: '#94a3b8' }}>
          Show a system notification when a dangerous site is detected.
        </p>
      </div>
      <button
        onClick={handleToggle}
        style={{
          width: 40, height: 22, borderRadius: 11, border: 'none',
          background: enabled ? '#f59e0b' : '#2a2d3e', cursor: 'pointer',
          position: 'relative', transition: 'background 0.2s', flexShrink: 0,
        }}
      >
        <span style={{
          position: 'absolute', top: 3, left: enabled ? 21 : 3,
          width: 16, height: 16, borderRadius: '50%', background: '#f8fafc',
          transition: 'left 0.2s',
        }} />
      </button>
    </div>
  )
}

function CacheSettings() {
    const [clearing, setClearing] = useState(false)
    const [cleared, setCleared] = useState(false)
    const [cacheCount, setCacheCount] = useState(0)

    useEffect(() => {
      chrome.storage.local.get('persistentApiCache').then(({ persistentApiCache = {} }) => {
        setCacheCount(Object.keys(persistentApiCache).length)
      })
    }, [])

    async function handleClearCache() {
      setClearing(true)
      await chrome.runtime.sendMessage({ type: 'CLEAR_ALL_CACHE' })
      setCacheCount(0)
      setClearing(false)
      setCleared(true)
      setTimeout(() => setCleared(false), 2000)
    }

    return (
      <div style={{
        background: '#1a1d2e',
        border: '1px solid #2a2d3e',
        borderRadius: 12,
        padding: 24,
        marginBottom: 24,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div>
          <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', marginBottom: 4 }}>
            Cached Scan Data
          </h2>
          <p style={{ fontSize: 12, color: '#94a3b8' }}>
            {cacheCount} domain{cacheCount !== 1 ? 's' : ''} cached to reduce API usage. Cleared automatically after 24 hours.
          </p>
        </div>
        <button
          onClick={handleClearCache}
          disabled={clearing || cacheCount === 0}
          style={{
            padding: '8px 14px',
            background: 'none',
            border: '1px solid rgba(239,68,68,0.3)',
            borderRadius: 8,
            color: '#ef4444',
            fontSize: 13,
            cursor: cacheCount === 0 ? 'default' : 'pointer',
            opacity: cacheCount === 0 ? 0.5 : 1,
            whiteSpace: 'nowrap',
          }}
        >
          {cleared ? 'Cleared' : 'Clear Cache'}
        </button>
      </div>
    )
  }


function SettingsPage({ whitelist, setWhitelist }) {
  const [apiKeys, setApiKeys] = useState({ gsb: '', ipqs: '', vt: '' })
  const [saved, setSaved] = useState(false)
  const [editing, setEditing] = useState({ gsb: false, ipqs: false, vt: false })
  const [testStatus, setTestStatus] = useState({ gsb: null, ipqs: null, vt: null })
  const [testing, setTesting] = useState({ gsb: false, ipqs: false, vt: false })

  async function handleTestKey(key) {
  if (!apiKeys[key]) return
  setTesting(prev => ({ ...prev, [key]: true }))
  setTestStatus(prev => ({ ...prev, [key]: null }))

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'TEST_API_KEY',
      service: key,
      key: apiKeys[key],
    })
    setTestStatus(prev => ({ ...prev, [key]: response }))
  } catch (err) {
    setTestStatus(prev => ({ ...prev, [key]: { success: false, message: err.message } }))
  } finally {
    setTesting(prev => ({ ...prev, [key]: false }))
  }
}

  const API_FIELDS = [
    {
      key: 'gsb',
      label: 'Google Safe Browsing',
      placeholder: 'AIza...',
      help: 'console.cloud.google.com',
    },
    {
      key: 'ipqs',
      label: 'IPQualityScore',
      placeholder: 'Your IPQS API key',
      help: 'ipqualityscore.com/user/settings',
    },
    {
      key: 'vt',
      label: 'VirusTotal',
      placeholder: 'Your VT API key',
      help: 'virustotal.com/gui/user/apikey',
    },
  ]

  useEffect(() => {
    chrome.storage.local.get('apiKeys').then(({ apiKeys: stored }) => {
      if (stored) setApiKeys(stored)
    })
  }, [])

  async function handleSaveKeys() {
    await chrome.storage.local.set({ apiKeys })
    setEditing({ gsb: false, ipqs: false, vt: false })
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }
  async function removeFromWhitelist(domain) {
    const updated = whitelist.filter(d => d !== domain)
    await chrome.storage.local.set({ whitelist: updated })
    setWhitelist(updated)
  }

  async function clearWhitelist() {
    await chrome.storage.local.set({ whitelist: [] })
    setWhitelist([])
  }

  const inputStyle = {
    width: '100%',
    padding: '9px 12px',
    background: '#0f1117',
    border: '1px solid #2a2d3e',
    borderRadius: 8,
    color: '#f8fafc',
    fontSize: 13,
    fontFamily: 'monospace',
    outline: 'none',
  }


  return (
    <div style={{ padding: 32, maxWidth: 640, margin: '0 auto' }}>
      <h1 style={{ fontSize: 22, fontWeight: 700, color: '#f8fafc', marginBottom: 8 }}>
        Settings
      </h1>
      <p style={{ fontSize: 14, color: '#94a3b8', marginBottom: 32 }}>
        Manage your extension preferences.
      </p>

      <div style={{
        background: '#1a1d2e',
        border: '1px solid #2a2d3e',
        borderRadius: 12,
        padding: 24,
        marginBottom: 24,
      }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', marginBottom: 4 }}>
          API Keys
        </h2>
        <p style={{ fontSize: 12, color: '#94a3b8', marginBottom: 20 }}>
          Keys are stored locally and never transmitted to any server other than the respective APIs.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {API_FIELDS.map(({ key, label, placeholder, help }) => (
            <div key={key}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <label style={{ fontSize: 13, color: '#f8fafc', fontWeight: 500 }}>
                  {label}
                </label>
                <a
                  href={`https://${help}`}
                  target="_blank"
                  rel="noreferrer"
                  style={{ fontSize: 11, color: '#f59e0b', textDecoration: 'none' }}
                >
                  Get key ↗
                </a>
              </div>
              {!editing[key] && apiKeys[key] ? (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  padding: '9px 12px',
                  background: '#0f1117',
                  border: '1px solid #2a2d3e',
                  borderRadius: 8,
                  gap: 8,
                }}>
                  <span style={{ flex: 1, fontSize: 13, color: '#94a3b8', fontFamily: 'monospace' }}>
                    {'•'.repeat(20)}{apiKeys[key].slice(-4)}
                  </span>

                  {testStatus[key] && (
                    <span style={{
                      fontSize: 11,
                      color: testStatus[key].success ? '#10b981' : '#ef4444',
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4,
                    }}>
                      {testStatus[key].success ? <ShieldCheck size={12} /> : <X size={12} />}
                      {testStatus[key].message}
                    </span>
                  )}
                  <button
                    onClick={() => handleTestKey(key)}
                    disabled={testing[key]}
                    style={{
                      background: 'none',
                      border: '1px solid #2a2d3e',
                      borderRadius: 6,
                      color: '#94a3b8',
                      fontSize: 11,
                      cursor: 'pointer',
                      padding: '2px 8px',
                    }}
                  >
                    {testing[key] ? 'Testing...' : 'Test'}
                  </button>

                  <button
                    onClick={() => {
                      setApiKeys(prev => ({ ...prev, [key]: '' }))
                      setEditing(prev => ({ ...prev, [key]: true }))
                    }}
                    style={{
                      background: 'none',
                      border: '1px solid #2a2d3e',
                      borderRadius: 6,
                      color: '#94a3b8',
                      fontSize: 11,
                      cursor: 'pointer',
                      padding: '2px 8px',
                    }}
                  >
                    Edit
                  </button>
                </div>
              ) : (
                <input
                  type="password"
                  placeholder={placeholder}
                  value={apiKeys[key]}
                  onChange={(e) => setApiKeys(prev => ({ ...prev, [key]: e.target.value }))}
                  style={inputStyle}
                  autoFocus={editing[key]}
                />
              )}
            </div>
          ))}
        </div>

        <button
          onClick={handleSaveKeys}
          style={{
            marginTop: 20,
            width: '100%',
            padding: '10px 0',
            background: saved ? '#10b981' : '#f59e0b',
            border: 'none',
            borderRadius: 8,
            color: '#0f1117',
            fontSize: 14,
            fontWeight: 600,
            cursor: 'pointer',
            transition: 'background 0.2s',
          }}
        >
          {saved ? 'Saved successfully' : 'Save API Keys'}
        </button>
      </div>

      <ThresholdSettings />
      <NotificationSettings />
      <CacheSettings />

      {/* Whitelist */}
      <div style={{
        background: '#1a1d2e',
        border: '1px solid #2a2d3e',
        borderRadius: 12,
        padding: 24,
        marginBottom: 24,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 16 }}>
          <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', flex: 1 }}>
            Whitelisted Domains
          </h2>
          {whitelist.length > 0 && (
            <button
              onClick={clearWhitelist}
              style={{
                background: 'none',
                border: '1px solid rgba(239,68,68,0.3)',
                borderRadius: 6,
                color: '#ef4444',
                fontSize: 12,
                cursor: 'pointer',
                padding: '4px 10px',
              }}
            >
              Clear All
            </button>
          )}
        </div>

        {whitelist.length === 0 ? (
          <p style={{ fontSize: 13, color: '#94a3b8' }}>
            No whitelisted domains. Sites you whitelist will appear here.
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {whitelist.map(domain => (
              <div key={domain} style={{
                display: 'flex',
                alignItems: 'center',
                padding: '10px 14px',
                background: '#0f1117',
                borderRadius: 8,
                gap: 10,
              }}>
                <ShieldCheck size={14} color="#10b981" />
                <span style={{ flex: 1, fontSize: 13, color: '#f8fafc' }}>
                  {domain}
                </span>
                <button
                  onClick={() => removeFromWhitelist(domain)}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: '#94a3b8',
                    cursor: 'pointer',
                    padding: 4,
                    display: 'flex',
                    alignItems: 'center',
                  }}
                >
                  <X size={14} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* About */}
      <div style={{
        background: '#1a1d2e',
        border: '1px solid #2a2d3e',
        borderRadius: 12,
        padding: 24,
      }}>
        <h2 style={{ fontSize: 15, fontWeight: 600, color: '#f8fafc', marginBottom: 16 }}>
          About
        </h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            { label: 'Version', value: '1.0.0' },
            { label: 'Author',  value: 'Yessine' },
            { label: 'APIs',    value: 'Google Safe Browsing · IPQualityScore · VirusTotal' },
          ].map(({ label, value }) => (
            <div key={label} style={{ display: 'flex', gap: 12 }}>
              <span style={{ fontSize: 13, color: '#94a3b8', minWidth: 80 }}>{label}</span>
              <span style={{ fontSize: 13, color: '#f8fafc' }}>{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function DashboardSkeleton() {
  return (
    <div style={{ padding: 32 }}>
      <div style={{ width: 140, height: 24, background: '#1a1d2e', borderRadius: 6, marginBottom: 12 }} />
      <div style={{ width: 240, height: 14, background: '#1a1d2e', borderRadius: 6, marginBottom: 32 }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
        {[0, 1, 2, 3].map(i => (
          <div key={i} style={{ height: 100, background: '#1a1d2e', borderRadius: 12 }} />
        ))}
      </div>
    </div>
  )
}


function OnboardingFlow({ onFinish }) {
  const [step, setStep] = useState(0)
  const [apiKeys, setApiKeys] = useState({ gsb: '', ipqs: '', vt: '' })

  const steps = [
    {
      title: 'Welcome to Linkscope',
      body: "This extension checks every site you visit against three independent threat databases and runs its own domain analysis to catch typosquatting and lookalike attacks. To get started, you'll need three free API keys. It takes about 3 minutes.",
    },
    {
      title: 'Google Safe Browsing',
      body: "Google's database of known malicious URLs. Get a free key from Google Cloud Console.",
      key: 'gsb',
      link: 'https://console.cloud.google.com',
    },
    {
      title: 'IPQualityScore',
      body: 'Domain reputation, fraud scoring, and phishing detection. Free tier includes 5,000 lookups per month.',
      key: 'ipqs',
      link: 'https://www.ipqualityscore.com/create-account',
    },
    {
      title: 'VirusTotal',
      body: 'Aggregates results from 70+ antivirus engines. Free tier includes 500 requests per day.',
      key: 'vt',
      link: 'https://www.virustotal.com/gui/join-us',
    },
    {
      title: "You're all set",
      body: 'Your keys are stored locally and never leave your browser except to talk directly to each service. You can change them anytime in Settings.',
    },
  ]

  const current = steps[step]
  const isLast = step === steps.length - 1
  const isFirst = step === 0

  async function handleNext() {
    if (isLast) {
      await chrome.storage.local.set({ apiKeys })
      onFinish()
      return
    }
    setStep(step + 1)
  }

  function handleSkip() {
    onFinish()
  }

  return (
    <div style={{
      minHeight: '100vh',
      background: '#0f1117',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 24,
    }}>
      <div style={{
        background: '#1a1d2e',
        border: '1px solid #2a2d3e',
        borderRadius: 16,
        padding: 40,
        maxWidth: 480,
        width: '100%',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 24 }}>
          <Shield size={20} color="#f59e0b" />
          <span style={{ fontSize: 13, color: '#94a3b8' }}>
            Step {step + 1} of {steps.length}
          </span>
        </div>

        {/* Progress dots */}
        <div style={{ display: 'flex', gap: 6, marginBottom: 28 }}>
          {steps.map((_, i) => (
            <div key={i} style={{
              flex: 1,
              height: 3,
              borderRadius: 2,
              background: i <= step ? '#f59e0b' : '#2a2d3e',
              transition: 'background 0.2s',
            }} />
          ))}
        </div>

        <h2 style={{ fontSize: 20, fontWeight: 700, color: '#f8fafc', marginBottom: 12 }}>
          {current.title}
        </h2>
        <p style={{ fontSize: 14, color: '#94a3b8', lineHeight: 1.6, marginBottom: 24 }}>
          {current.body}
        </p>

        {current.key && (
          <div style={{ marginBottom: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
              <label style={{ fontSize: 13, color: '#f8fafc', fontWeight: 500 }}>
                API Key
              </label>
              <a
                href={current.link}
                target="_blank"
                rel="noreferrer"
                style={{ fontSize: 12, color: '#f59e0b', textDecoration: 'none' }}
              >
                Get free key ↗
              </a>
            </div>
            <input
              type="password"
              placeholder="Paste your API key here"
              value={apiKeys[current.key]}
              onChange={e => setApiKeys(prev => ({ ...prev, [current.key]: e.target.value }))}
              style={{
                width: '100%',
                padding: '10px 12px',
                background: '#0f1117',
                border: '1px solid #2a2d3e',
                borderRadius: 8,
                color: '#f8fafc',
                fontSize: 13,
                outline: 'none',
              }}
            />
            <p style={{ fontSize: 11, color: '#57534e', marginTop: 6 }}>
              You can skip this and add it later in Settings.
            </p>
          </div>
        )}

        <div style={{ display: 'flex', gap: 8 }}>
          {!isFirst && (
            <button
              onClick={() => setStep(step - 1)}
              style={{
                padding: '10px 16px',
                background: 'none',
                border: '1px solid #2a2d3e',
                borderRadius: 8,
                color: '#94a3b8',
                fontSize: 13,
                cursor: 'pointer',
              }}
            >
              Back
            </button>
          )}
          <button
            onClick={handleSkip}
            style={{
              padding: '10px 16px',
              background: 'none',
              border: '1px solid #2a2d3e',
              borderRadius: 8,
              color: '#94a3b8',
              fontSize: 13,
              cursor: 'pointer',
            }}
          >
            Skip setup
          </button>
          <button
            onClick={handleNext}
            style={{
              flex: 1,
              padding: '10px 16px',
              background: '#f59e0b',
              border: 'none',
              borderRadius: 8,
              color: '#0f1117',
              fontSize: 14,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            {isLast ? 'Finish' : 'Continue'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Dashboard() {
  const [page, setPage] = useState('overview')
  const [history, setHistory] = useState([])
  const [whitelist, setWhitelist] = useState([])
  const [detailEntry, setDetailEntry] = useState(null)
  const [collapsed, setCollapsed] = useState(false)
  const [loading, setLoading] = useState(true)
  const [showOnboarding, setShowOnboarding] = useState(() => {
    const params = new URLSearchParams(window.location.search)
    return params.get('onboarding') === 'true'
  })


  useEffect(() => {
    chrome.storage.local.get(['scanHistory', 'whitelist']).then(data => {
      setHistory(data.scanHistory ?? [])
      setWhitelist(data.whitelist ?? [])
      setLoading(false)
    })

    const interval = setInterval(() => {
      chrome.storage.local.get(['scanHistory', 'whitelist']).then(data => {
        setHistory(data.scanHistory ?? [])
        setWhitelist(data.whitelist ?? [])
      })
    }, 5000)

    return () => clearInterval(interval)
  }, [])

  function finishOnboarding() {
    setShowOnboarding(false)
    window.history.replaceState({}, '', window.location.pathname)
  }

  if (showOnboarding) {
    return <OnboardingFlow onFinish={finishOnboarding} />
  }

  const pages = {
    overview: <OverviewPage history={history} setDetailEntry={setDetailEntry} setPage={setPage} />,
    history:  <HistoryPage history={history} setHistory={setHistory} setDetailEntry={setDetailEntry} setPage={setPage} />,
    detail:   <DetailPage entry={detailEntry} setPage={setPage} />,
    settings: <SettingsPage whitelist={whitelist} setWhitelist={setWhitelist} />,
  }

  return (
    <div style={{
      display: 'flex',
      minHeight: '100vh',
      background: '#0f1117',
      color: '#f8fafc',
    }}>
      <Sidebar page={page} setPage={setPage} collapsed={collapsed} setCollapsed={setCollapsed} />
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {loading ? <DashboardSkeleton /> : pages[page]}
      </div>
    </div>
  )
}