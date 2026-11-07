/* global chrome */

import { analyzeDomain } from './domainAnalyzer.js'
import { checkGoogleSafeBrowsing } from './googleSafeBrowsing.js'
import { checkIPQualityScore } from './ipQualityScore.js'
import { checkVirusTotal } from './virusTotal.js'
import { calculateRiskScore, DEFAULT_THRESHOLDS } from './riskScorer.js'
import { getCacheKey, shouldSkipURL, isPrivateURL } from '../utils/urlUtils.js'

import { parseUrl } from '../core/url.js'
import { ALLOWED_DOMAINS } from '../core/brands.js'

const apiResultsCache = new Map()
const pendingAnalyses = new Map()

const CACHE_TTL_MS = 24 * 60 * 60 * 1000
const INCOMPLETE_TTL_MS = 5 * 60 * 1000
const MAX_CACHED_DOMAINS = 200

// Cache writes run one at a time, so two finishing analyses can't overwrite each other.
let cacheQueue = Promise.resolve()
function withCacheLock(task) {
  const run = cacheQueue.then(task)
  cacheQueue = run.catch(() => {})
  return run
}

// A result with failed sources is only trusted briefly, then re-checked.
function ttlFor(data) {
  return data?.failedSources?.length ? INCOMPLETE_TTL_MS : CACHE_TTL_MS
}

export function clearAllApiCache() {
  apiResultsCache.clear()
}

async function getCachedApiResults(cacheKey) {
  const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
  const entry = persistentApiCache[cacheKey]
  if (!entry) return null
  if (Date.now() - entry.timestamp > ttlFor(entry.data)) return null
  return entry.data
}

function setCachedApiResults(cacheKey, data) {
  return withCacheLock(async () => {
    const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
    persistentApiCache[cacheKey] = { data, timestamp: Date.now() }

    const keys = Object.keys(persistentApiCache)
    if (keys.length > MAX_CACHED_DOMAINS) {
      keys.sort((a, b) => persistentApiCache[a].timestamp - persistentApiCache[b].timestamp)
      for (const key of keys.slice(0, keys.length - MAX_CACHED_DOMAINS)) {
        delete persistentApiCache[key]
      }
    }

    await chrome.storage.local.set({ persistentApiCache })
  })
}

export async function analyzeURL(url, contentResult = {}, { ignoreWhitelist = false } = {}) {
  if (shouldSkipURL(url) || isPrivateURL(url)) return null

  const cacheKey = getCacheKey(url)

  // Settings are read BEFORE anything is sent anywhere, so a whitelisted site never reaches the APIs.
  const [{ whitelist = [] }, { riskThresholds }] = await Promise.all([
    chrome.storage.local.get('whitelist'),
    chrome.storage.local.get('riskThresholds'),
  ])

  if (!ignoreWhitelist && whitelist.includes(cacheKey)) {
    console.log('Whitelisted:', cacheKey)
    return null
  }

  // Check-and-reserve with no await in between: two simultaneous calls can't both start a fetch.
  if (!pendingAnalyses.has(cacheKey)) {
    const promise = fetchRawApiResults(url, cacheKey).finally(() => {
      pendingAnalyses.delete(cacheKey)
    })
    pendingAnalyses.set(cacheKey, promise)
  }
  const rawApiData = await pendingAnalyses.get(cacheKey)

  const thresholds = riskThresholds ?? DEFAULT_THRESHOLDS
  const { gsbResult, ipqsResult, vtResult, dataFetchedAt } = rawApiData
  const failedSources = rawApiData.failedSources ?? []
  const domainResult = analyzeDomain(url)

  const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
  result.dataFetchedAt = dataFetchedAt
  result.incomplete = failedSources.length > 0
  result.failedSources = failedSources

  if (result.incomplete) {
    result.reasons.push(
      `Could not check ${failedSources.join(', ')}, so this result may be incomplete`
    )
  }

  console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)
  return result
}

function isBareBrandHost(url) {
  const p = parseUrl(url)
  if (!p || !p.registrableDomain) return false
  return (
    ALLOWED_DOMAINS.has(p.registrableDomain) &&
    (p.hostname === p.registrableDomain || p.hostname === `www.${p.registrableDomain}`)
  )
}

async function fetchRawApiResults(url, cacheKey) {
  const inMemory = apiResultsCache.get(cacheKey)
  if (inMemory) {
    if (Date.now() - inMemory.dataFetchedAt <= ttlFor(inMemory)) {
      console.log('API cache hit:', cacheKey)
      return inMemory
    }
    apiResultsCache.delete(cacheKey)
  }

  const persisted = await getCachedApiResults(cacheKey)
  if (persisted) {
    console.log('Persistent cache hit:', cacheKey)
    return persisted
  }

  console.log('Analyzing URL:', url)
  const domainResult = analyzeDomain(url)

  const [gsbSettled, ipqsSettled] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkIPQualityScore(url),
  ])

  const gsbResult = gsbSettled.status === 'fulfilled'
    ? gsbSettled.value
    : { isThreat: false, threatType: null, error: true }

  const ipqsResult = ipqsSettled.status === 'fulfilled'
    ? ipqsSettled.value
    : { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }

  const preliminary = calculateRiskScore(domainResult, gsbResult, ipqsResult, null, {}, DEFAULT_THRESHOLDS)

  let vtResult = { isThreat: false, detectionCount: 0, engineCount: 0, error: false }
  if (preliminary.score <= 70 && !isBareBrandHost(url)) {
    vtResult = await checkVirusTotal(url)
  } else {
    console.log('Skipping VT for', cacheKey)
  }

  const failedSources = []
  if (gsbResult.error) failedSources.push('Google Safe Browsing')
  if (ipqsResult.error) failedSources.push('IPQualityScore')
  if (vtResult.error) failedSources.push(vtResult.rateLimited ? 'VirusTotal (rate limit reached)' : 'VirusTotal')

  const apiData = { gsbResult, ipqsResult, vtResult, failedSources, dataFetchedAt: Date.now() }

  apiResultsCache.set(cacheKey, apiData)
  try {
    await setCachedApiResults(cacheKey, apiData)
  } catch (err) {
    console.warn('Could not persist API cache:', err)
  }

  return apiData
}

export async function clearCacheForURL(url) {
  const cacheKey = getCacheKey(url)
  apiResultsCache.delete(cacheKey)
  pendingAnalyses.delete(cacheKey)

  await withCacheLock(async () => {
    const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
    delete persistentApiCache[cacheKey]
    await chrome.storage.local.set({ persistentApiCache })
  })
}