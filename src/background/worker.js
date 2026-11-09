/* global chrome */

import { collectRaw, analyzeURL, clearCacheForURL, clearAllApiCache } from './urlAnalyzer.js'
import { shouldSkipURL, normalizeURL, getCacheKey, isPrivateURL } from '../utils/urlUtils.js'
import { analyzeDomain } from './domainAnalyzer.js'
import { TOP_GLOBAL_DOMAINS, KNOWN_REDIRECT_SERVICES } from '../core/brands.js'
import { extractDomainFromHostname, isHTTPS } from '../utils/domainUtils.js'
import { buildResult, buildContentResult, hasEscalated } from './verdict.js'
import { DEFAULT_THRESHOLDS } from './riskScorer.js'


const redirectChains = new Map()
const redirectResults = new Map()

// One entry per tab: the analysis of the page currently loaded there.
const pageSessions = new Map()

// Bumped by "Delete all scan data"; work started before a delete must not write results afterward.
let dataEpoch = 0

const SETTLE_DELAY_MS = 400   // pages that redirect away immediately aren't worth scanning
const CONTENT_GRACE_MS = 3000 // how long after load to wait for the content script

async function tabIsStillOn(tabId, url) {
  try {
    const tab = await chrome.tabs.get(tabId)
    return normalizeURL(tab.url) === normalizeURL(url)
  } catch {
    return false
  }
}

async function writeStatus(tabId, url, state) {
  await chrome.storage.local.set({
    [`status_${tabId}`]: { url, state, timestamp: Date.now() },
  })
}

async function saveToHistory(url, result) {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory')

  const entry = {
    url,
    score: result.score,
    riskLevel: result.riskLevel.label,
    timestamp: Date.now(),
    dataFetchedAt: result.dataFetchedAt ?? Date.now(),
    reasons: result.reasons,
    signals: result.signals,
    securityHeaders: {
      hasCSP: result.hasCSP,
      hasHSTS: result.hasHSTS,
      hasXFrameOptions: result.hasXFrameOptions,
      hasXContentTypeOptions: result.hasXContentTypeOptions,
    },
  }

 
  const mostRecentForUrl = scanHistory.find(h => normalizeURL(h.url) === normalizeURL(url))
  if (mostRecentForUrl && mostRecentForUrl.dataFetchedAt === entry.dataFetchedAt) {
    return
  }

  // Add new entry at the beginning so history is newest-first
  const updated = [entry, ...scanHistory]

  if (updated.length > 500) updated.splice(500)

  await chrome.storage.local.set({ scanHistory: updated })
}


async function saveLinkCheck(url, result) {
  const { linkChecks = [] } = await chrome.storage.local.get('linkChecks')

  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

  const entry = {
    id,
    url,
    score: result.score,
    riskLevel: result.riskLevel.label,
    timestamp: Date.now(),
    dataFetchedAt: result.dataFetchedAt ?? Date.now(),
    reasons: result.reasons,
    signals: result.signals,
    securityHeaders: {
      hasCSP: result.hasCSP,
      hasHSTS: result.hasHSTS,
      hasXFrameOptions: result.hasXFrameOptions,
      hasXContentTypeOptions: result.hasXContentTypeOptions,
    },
  }

  const updated = [entry, ...linkChecks]
  if (updated.length > 200) updated.splice(200)

  await chrome.storage.local.set({ linkChecks: updated })
  return id
}

chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== 'check-link') return
  const linkUrl = info.linkUrl
  if (!linkUrl || shouldSkipURL(linkUrl)) return

  const epoch = dataEpoch
  const analysis = await analyzeURL(linkUrl, {}, { ignoreWhitelist: true })
  if (!analysis) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Link Check',
      message: 'This link could not be analyzed (private network or unreachable).',
    })
    return
  }

  const result = analysis.final ? await analysis.final : analysis.result

  if (epoch !== dataEpoch) return

  const id = await saveLinkCheck(linkUrl, result)

  const firstReason = result.reasons[0] || 'No specific threats detected.'
  const message = result.reasons.length > 1
    ? `Score ${result.score}/100 - ${firstReason} (+${result.reasons.length - 1} more - click for full details)`
    : `Score ${result.score}/100 - ${firstReason}`

  chrome.notifications.create(`linkcheck-${id}`, {
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: `Link Check: ${result.riskLevel.label}`,
    message,
  })
})

chrome.notifications.onClicked.addListener(async (notificationId) => {
  if (!notificationId.startsWith('linkcheck-')) return
  const id = notificationId.slice('linkcheck-'.length)

  const dashboardPath = 'src/dashboard/dashboard.html'
  const dashboardUrl = chrome.runtime.getURL(`${dashboardPath}?linkCheck=${encodeURIComponent(id)}`)

  const tabs = await chrome.tabs.query({ url: chrome.runtime.getURL(`${dashboardPath}*`) })
  if (tabs.length > 0) {
    await chrome.tabs.update(tabs[0].id, { active: true, url: dashboardUrl })
    await chrome.windows.update(tabs[0].windowId, { focused: true })
  } else {
    await chrome.tabs.create({ url: dashboardUrl })
  }

  chrome.notifications.clear(notificationId)
})

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return
  const tabId = details.tabId

  redirectChains.set(tabId, [details.url])
  redirectResults.delete(tabId)
  securityHeadersResults.delete(tabId)
  chrome.storage.local.remove([`result_${tabId}`, `status_${tabId}`])
})

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return
  if (details.transitionQualifiers?.includes('server_redirect') ||
      details.transitionQualifiers?.includes('client_redirect')) {
    const tabId = details.tabId
    if (!redirectChains.has(tabId)) {
      redirectChains.set(tabId, [])
    }
    redirectChains.get(tabId).push(details.url)
  }
})

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return
  if (shouldSkipURL(details.url)) {
    pageSessions.delete(details.tabId)
    return
  }
  startPageAnalysis(details.tabId, details.url)
})

chrome.webNavigation.onCompleted.addListener(async (details) => {
  const { extensionEnabled } = await chrome.storage.local.get('extensionEnabled')
  if (extensionEnabled === false) return
  if (details.frameId !== 0) return

  const url = details.url
  if (shouldSkipURL(url)) return

  const tabId = details.tabId

  const chain = redirectChains.get(tabId) ?? []
  redirectChains.delete(tabId)


  const validChain = chain.filter(u => {
  try { 
    const parsed = new URL(u)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch { 
    return false 
  }
})

  const getBase = u => { try { return extractDomainFromHostname(new URL(u).hostname) } catch { return u } }

  const untrustedChain = validChain.filter(u => {
  try {
    const hostname = new URL(u).hostname
    if(KNOWN_REDIRECT_SERVICES.has(hostname)) return false
    const parts = hostname.split('.')
    const baseDomain =  parts.length >= 2 ? parts[parts.length - 2] : hostname
    return !TOP_GLOBAL_DOMAINS.has(baseDomain)
  } catch { return false }
})

  const uniqueDomains = new Set(untrustedChain.map(getBase))

  const redirectResult = {
    hasRedirectChain: untrustedChain.length > 2 && uniqueDomains.size > 1,
    redirectCount: validChain.length,
    redirectChain: validChain.map(u => {
      try { return new URL(u).hostname } catch { return u }
    }),
  }

  redirectResults.set(tabId, redirectResult)

    // If the content script hasn't reported a few seconds after load, stop waiting for it.
  const session = pageSessions.get(tabId)
  if (session && !session.contentDone) {
    setTimeout(() => {
      if (pageSessions.get(tabId) !== session || session.contentDone) return
      session.contentDone = true
      scheduleRefresh(tabId, session)
    }, CONTENT_GRACE_MS)
  }
})



chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`result_${tabId}`, `status_${tabId}`])
  redirectResults.delete(tabId)
  securityHeadersResults.delete(tabId)
  pageSessions.delete(tabId)
})

chrome.runtime.onInstalled.addListener(async (details) => {
  const { apiKeys } = await chrome.storage.local.get('apiKeys')
  if (!apiKeys) {
    await chrome.storage.local.set({
      apiKeys: { gsb: '', ipqs: '', vt: '',}
    })
  }

  chrome.contextMenus.create({
    id: 'check-link',
    title: 'Check this link for phishing',
    contexts: ['link'],
  })

  if (details.reason === 'install') {
    chrome.tabs.create({ url: chrome.runtime.getURL('src/dashboard/dashboard.html?onboarding=true') })
  }

  console.log('Linkscope installed and ready.')
})

const securityHeadersResults = new Map()

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    if (details.type !== 'main_frame') return

    const headers = details.responseHeaders || []
    const getHeader = name => headers.find(h => h.name.toLowerCase() === name.toLowerCase())

    const hasCSP = !!getHeader('content-security-policy')
    const hasHSTS = !!getHeader('strict-transport-security')
    const hasXFrameOptions = !!getHeader('x-frame-options')
    const hasXContentTypeOptions = !!getHeader('x-content-type-options')

    securityHeadersResults.set(details.tabId, {
      hasCSP,
      hasHSTS,
      hasXFrameOptions,
      hasXContentTypeOptions,
    })
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
)

async function isEnabled() {
  const { extensionEnabled } = await chrome.storage.local.get('extensionEnabled')
  return extensionEnabled !== false
}

function attachHeaders(result, content) {
  result.hasCSP = content.hasCSP
  result.hasHSTS = content.hasHSTS
  result.hasXFrameOptions = content.hasXFrameOptions
  result.hasXContentTypeOptions = content.hasXContentTypeOptions
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function isCurrent(tabId, session) {
  return pageSessions.get(tabId) === session
}

function newSession(url) {
  return {
    url,
    headers: {},
    redirect: {},
    page: {},
    raw: null,
    contentDone: false,
    epoch: dataEpoch,
    settled: false,
    notified: false,
    shownLevel: null,
    queue: Promise.resolve(),
  }
}

async function getThresholds() {
  const { riskThresholds } = await chrome.storage.local.get('riskThresholds')
  return riskThresholds ?? DEFAULT_THRESHOLDS
}

function evaluate(session, thresholds) {
  const content = buildContentResult({
    page: session.page,
    redirect: session.redirect,
    headers: session.headers,
    isHttps: isHTTPS(session.url),
  })
  const result = buildResult({
    domainResult: analyzeDomain(session.url),
    raw: session.raw,
    contentResult: content,
    thresholds,
  })
  attachHeaders(result, content)
  return result
}

async function publish(tabId, session, result) {
  if (!isCurrent(tabId, session) || !(await tabIsStillOn(tabId, session.url))) return

  await chrome.storage.local.set({
    [`result_${tabId}`]: { url: session.url, ...result, timestamp: Date.now() },
  })
  await writeStatus(tabId, session.url, 'done')

  // Warn when the level is higher than the last warning the page actually confirmed.
  const label = result.riskLevel.label
  if (hasEscalated(session.shownLevel ?? 'SAFE', label)) {
    chrome.tabs.sendMessage(tabId, { type: 'ANALYSIS_RESULT', url: session.url, result })
      .then(response => {
        if (response?.received !== true) return
        if (!session.shownLevel || hasEscalated(session.shownLevel, label)) session.shownLevel = label
      })
      .catch(() => {}) // the content script isn't running (yet); the next refresh tries again
  }

  if (label === 'DANGEROUS' && !session.notified) {
    session.notified = true
    await notifyDangerous(session.url, result)
  }
}

// History is written once per page: when the verdict is final and the page signals are in.
async function maybeSettle(session, result) {
  if (session.settled || session.epoch !== dataEpoch || !session.contentDone || result.pending.length > 0) return
  session.settled = true
  await saveToHistory(session.url, result)
}

async function refresh(tabId, session) {
  if (!session.raw || session.epoch !== dataEpoch) return

  if (!(await isEnabled())) {
    if (isCurrent(tabId, session)) {
      await chrome.storage.local.remove([`result_${tabId}`, `status_${tabId}`])
    }
    return
  }

  const result = evaluate(session, await getThresholds())
  const stage = result.pending.length > 0 ? 'fast result' : 'complete'
  console.log(`Analysis ${stage}: ${session.url} → score ${result.score} (${result.riskLevel.label})`)

  await publish(tabId, session, result)
  await maybeSettle(session, result)
}

// Refreshes for one page run one at a time, so an older result can't overwrite a newer one.
function scheduleRefresh(tabId, session) {
  session.queue = session.queue
    .then(() => refresh(tabId, session))
    .catch(err => console.error('Linkscope refresh failed:', err))
  return session.queue
}

async function runPageAnalysis(tabId, session) {
  const { url } = session
  if (!(await isEnabled())) return

  await sleep(SETTLE_DELAY_MS)
  if (!isCurrent(tabId, session)) return

  const { whitelist = [] } = await chrome.storage.local.get('whitelist')
  if (!isCurrent(tabId, session)) return

  if (whitelist.includes(getCacheKey(url))) {
    await writeStatus(tabId, url, 'whitelisted')
    return
  }
  if (isPrivateURL(url)) {
    await writeStatus(tabId, url, 'skipped')
    return
  }

  await writeStatus(tabId, url, 'analyzing')

  let collected
  try {
    collected = await collectRaw(url)
  } catch (err) {
    console.error('Linkscope analysis failed:', err)
    if (isCurrent(tabId, session)) await writeStatus(tabId, url, 'error')
    return
  }

  if (!collected) {
    if (isCurrent(tabId, session)) await writeStatus(tabId, url, 'skipped')
    return
  }

  // Phase 1: warn as soon as the fast sources have spoken.
  session.raw = collected.raw
  await scheduleRefresh(tabId, session)

  if (!collected.final) return

  // Phase 2: VirusTotal finished.
  session.raw = await collected.final
  await scheduleRefresh(tabId, session)
}

function startPageAnalysis(tabId, url) {
  const session = newSession(url)
  pageSessions.set(tabId, session)
  session.headers = securityHeadersResults.get(tabId) ?? {}

  runPageAnalysis(tabId, session).catch(err => console.error('Linkscope analysis failed:', err))
  return session
}

// The content script reports page signals; they are merged into the page's session.
async function handleContentAnalysis(message, sender) {
  if (!(await isEnabled())) return

  const tabId = sender.tab?.id
  const url = sender.tab?.url
  if (!tabId || !url || shouldSkipURL(url)) return

  let session = pageSessions.get(tabId)
  if (!session || normalizeURL(session.url) !== normalizeURL(url)) {
    // No analysis was started for this page (for example, the worker restarted mid-load).
    session = startPageAnalysis(tabId, url)
  }

  session.page = message.contentResult ?? {}
  session.redirect = redirectResults.get(tabId) ?? {}
  redirectResults.delete(tabId)
  session.contentDone = true

  if (session.raw) await scheduleRefresh(tabId, session)
}

async function notifyDangerous(url, result) {
  const { notificationsEnabled } = await chrome.storage.local.get('notificationsEnabled')
  if (notificationsEnabled === false) return
  let host = url
  try { host = new URL(url).hostname } catch { /* keep raw url */ }
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title: 'Dangerous Site Detected',
    message: `${host}: ${result.reasons[0] || 'This site has been flagged as dangerous.'}`,
  })
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  if (message.type === 'TEST_API_KEY') {
    const { service, key } = message;
    
    (async () => {
      try {
        let testUrl = 'https://www.google.com'
        let result = { success: false, message: 'Unknown service' }

        if (service === 'gsb') {
          const response = await fetch(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
            {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                client: { clientId: 'linkscope', clientVersion: '1.0.0' },
                threatInfo: {
                  threatTypes: ['MALWARE'],
                  platformTypes: ['ANY_PLATFORM'],
                  threatEntryTypes: ['URL'],
                  threatEntries: [{ url: testUrl }],
                },
              }),
            }
          )
          result = response.ok
            ? { success: true, message: 'Key is valid' }
            : { success: false, message: `Error ${response.status}` }
        }

        if (service === 'ipqs') {
          const response = await fetch(
            `https://www.ipqualityscore.com/api/json/url/${encodeURIComponent(key)}/${encodeURIComponent(testUrl)}`
          )
          const data = await response.json()
          result = data.success
            ? { success: true, message: 'Key is valid' }
            : { success: false, message: data.message || 'Invalid key' }
        }

        if (service === 'vt') {
          const response = await fetch('https://www.virustotal.com/api/v3/users/current', {
            headers: { 'x-apikey': key },
          })
          result = response.ok
            ? { success: true, message: 'Key is valid' }
            : { success: false, message: `Error ${response.status}` }
        }

        sendResponse(result)
      } catch (err) {
        sendResponse({ success: false, message: err.message })
      }
    })()

    return true
  }

  if (message.type === 'RESCAN') {
    const tabId = message.tabId
    const url = message.url
    if (!url) { sendResponse({ ok: false }); return true }
    
    ((async () => {
      await clearCacheForURL(url)
      await chrome.storage.local.remove([`result_${tabId}`, `status_${tabId}`])
      sendResponse({ ok: true })
    })())
    return true
  }

  if (message.type === 'CONTENT_ANALYSIS') {
    handleContentAnalysis(message, sender).catch(err => console.error('Linkscope analysis failed:', err))
    sendResponse({ received: true })
    return true
  }

  if (message.type === 'DELETE_ALL_DATA') {
    (async () => {
      dataEpoch++
      clearAllApiCache()
      redirectChains.clear()
      redirectResults.clear()
      securityHeadersResults.clear()
      const all = await chrome.storage.local.get(null)
      const perTab = Object.keys(all).filter(k => k.startsWith('result_') || k.startsWith('status_'))
      await chrome.storage.local.remove(['scanHistory', 'linkChecks', 'persistentApiCache', ...perTab])
      sendResponse({ ok: true })
    })()
    return true
  }

  if (message.type === 'CLEAR_ALL_CACHE') {
  clearAllApiCache()
  chrome.storage.local.remove('persistentApiCache').then(() => {
    sendResponse({ ok: true })
  })
  return true
}
})