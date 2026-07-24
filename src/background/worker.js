/* global chrome */

import { analyzeURL, clearCacheForURL, clearAllApiCache } from './urlAnalyzer.js'
import { shouldSkipURL, normalizeURL } from '../utils/urlUtils.js'
import { TOP_GLOBAL_DOMAINS, KNOWN_REDIRECT_SERVICES } from './domainAnalyzer.js'
import { extractDomainFromHostname } from '../utils/domainUtils.js'


const redirectChains = new Map()
const redirectResults = new Map()


async function saveToHistory(url, result) {
  const { scanHistory = [] } = await chrome.storage.local.get('scanHistory')

  const entry = {
    url,
    score: result.score,
    riskLevel: result.riskLevel.label,
    timestamp: Date.now(),
    dataFetchedAt: result.dataFetchedAt ?? Date.now(),
    reasons: result.score > 0 ? result.reasons : [],
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
    reasons: result.score > 0 ? result.reasons : [],
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

  
  const result = await analyzeURL(linkUrl, {}, { ignoreWhitelist: true })
  if (!result) {
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: 'Link Check',
      message: 'This link could not be analyzed (private network or unreachable).',
    })
    return
  }

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
})



chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`result_${tabId}`)
  redirectResults.delete(tabId)
  securityHeadersResults.delete(tabId)
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
      await chrome.storage.local.remove(`result_${tabId}`)
      sendResponse({ ok: true })
    })())
    return true
  }

  if (message.type === 'CONTENT_ANALYSIS') {
    chrome.storage.local.get('extensionEnabled').then(({ extensionEnabled }) => {
    if (extensionEnabled === false) return

    const tabId = sender.tab?.id
    const url = sender.tab?.url
    if (!tabId || !url || shouldSkipURL(url)) return

    const redirectResult = redirectResults.get(tabId) ?? {}
    redirectResults.delete(tabId)

    const securityHeaders = securityHeadersResults.get(tabId) ?? {}
    securityHeadersResults.delete(tabId)

    const mergedContentResult = {
      ...message.contentResult,
      hasRedirectChain: redirectResult.hasRedirectChain,
      redirectCount: redirectResult.redirectCount,
      redirectChain: redirectResult.redirectChain,
      hasCSP: securityHeaders.hasCSP,
      hasHSTS: securityHeaders.hasHSTS,
      hasXFrameOptions: securityHeaders.hasXFrameOptions,
      hasXContentTypeOptions: securityHeaders.hasXContentTypeOptions
    }

    analyzeURL(url, mergedContentResult).then(async result => {
      if (!result) return

      result.hasCSP = mergedContentResult.hasCSP
      result.hasHSTS = mergedContentResult.hasHSTS
      result.hasXFrameOptions = mergedContentResult.hasXFrameOptions
      result.hasXContentTypeOptions = mergedContentResult.hasXContentTypeOptions

      const { extensionEnabled: stillEnabled } = await chrome.storage.local.get('extensionEnabled')
      if (stillEnabled === false) return

      chrome.storage.local.set({
        [`result_${tabId}`]: {
          url,
          ...result,
          timestamp: Date.now(),
        }
      })

      await saveToHistory(url, result)

      if (result.riskLevel.label !== 'SAFE') {
        chrome.tabs.sendMessage(tabId, {
          type: 'ANALYSIS_RESULT',
          result,
        }).catch(() => {})
      }

      if (result.riskLevel.label === 'DANGEROUS') {
        
        const { notificationsEnabled } = await chrome.storage.local.get('notificationsEnabled')
        if (notificationsEnabled !== false) {
          chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon48.png',
            title: 'Dangerous Site Detected',
            message: result.reasons[0] || 'This site has been flagged as dangerous.',
          })
        }
      }
    })
  })
    sendResponse({ received: true })
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