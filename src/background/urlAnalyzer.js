/* global chrome */

import { analyzeDomain } from './domainAnalyzer.js'
import { checkGoogleSafeBrowsing } from './googleSafeBrowsing.js'
import { checkIPQualityScore } from './ipQualityScore.js'
import { checkVirusTotal } from './virusTotal.js'
import { calculateRiskScore, DEFAULT_THRESHOLDS } from './riskScorer.js'
import { buildResult, ttlFor, shouldQueryVirusTotal } from './verdict.js'
import { getCacheKey, shouldSkipURL, isPrivateURL } from '../utils/urlUtils.js'
import { parseUrl } from '../core/url.js'
import { ALLOWED_DOMAINS } from '../core/brands.js'


const apiResultsCache = new Map()

// One entry per site being analyzed right now: { fast, finalRaw }.
const inFlight = new Map()

const MAX_CACHED_DOMAINS = 200

// Cache writes run one at a time, so two finishing analyses can't overwrite each other.
let cacheQueue = Promise.resolve()
function withCacheLock(task) {
  const run = cacheQueue.then(task)
  cacheQueue = run.catch(() => {})
  return run
}

export function clearAllApiCache() {
  apiResultsCache.clear()
  inFlight.clear()
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

async function readCache(cacheKey) {
  const inMemory = apiResultsCache.get(cacheKey)
  if (inMemory) {
    if (Date.now() - inMemory.dataFetchedAt <= ttlFor(inMemory)) return inMemory
    apiResultsCache.delete(cacheKey)
  }
  return getCachedApiResults(cacheKey)
}

function isBareBrandHost(url) {
  const p = parseUrl(url)
  if (!p || !p.registrableDomain) return false
  return (
    ALLOWED_DOMAINS.has(p.registrableDomain) &&
    (p.hostname === p.registrableDomain || p.hostname === `www.${p.registrableDomain}`)
  )
}

// Store a finished result, unless a rescan or cache clear has replaced this analysis in the meantime.
function commit(cacheKey, entry, raw) {
  if (inFlight.get(cacheKey) !== entry) return Promise.resolve()
  apiResultsCache.set(cacheKey, raw)
  return setCachedApiResults(cacheKey, raw).catch(err => console.warn('Could not persist API cache:', err))
}

async function runFastPhase(url, cacheKey, entry) {
  const cached = await readCache(cacheKey)
  if (cached) {
    console.log('Cache hit:', cacheKey)
    entry.finalRaw = Promise.resolve(cached)
    return cached
  }

  console.log('Analyzing URL:', url)
  const domainResult = analyzeDomain(url)

  const [gsbSettled, ipqsSettled] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkIPQualityScore(url),
  ])

  const gsbResult = gsbSettled.status === 'fulfilled' ? gsbSettled.value : { isThreat: false, threatType: null, error: true }

  const ipqsResult = ipqsSettled.status === 'fulfilled' ? ipqsSettled.value : { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }

  const preliminary = calculateRiskScore(domainResult, gsbResult, ipqsResult, null, {}, DEFAULT_THRESHOLDS)
  const dataFetchedAt = Date.now()

  if (!shouldQueryVirusTotal(preliminary.score, isBareBrandHost(url))) {
    console.log('Skipping VT for', cacheKey)
    const raw = { gsbResult, ipqsResult, vtResult: null, vtState: 'skipped', dataFetchedAt }
    entry.finalRaw = commit(cacheKey, entry, raw).then(() => raw)
    return raw
  }

  // VirusTotal runs in the background; the fast result is returned right away.
  const fastRaw = { gsbResult, ipqsResult, vtResult: null, vtState: 'pending', dataFetchedAt }
  entry.finalRaw = checkVirusTotal(url)
    .catch(() => ({ isThreat: false, detectionCount: 0, engineCount: 0, error: true }))
    .then(vtResult => {
      const raw = { ...fastRaw, vtResult, vtState: 'done' }
      return commit(cacheKey, entry, raw).then(() => raw)
    })
  return fastRaw
}

function startAnalysis(url, cacheKey) {
  const entry = { fast: null, finalRaw: null }
  entry.fast = runFastPhase(url, cacheKey, entry)
  entry.fast
    .then(() => entry.finalRaw)
    .catch(() => {})
    .finally(() => {
      if (inFlight.get(cacheKey) === entry) inFlight.delete(cacheKey)
    })
  return entry
}

// Returns null when the URL is skipped or whitelisted. Otherwise { result, final }:
// `result` is ready after the fast sources; `final` is null when nothing is pending,
// or a promise for the complete result once VirusTotal has finished.
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

  // Check-and-reserve with no await in between: two simultaneous calls can't both start work.
  let entry = inFlight.get(cacheKey)
  if (!entry) {
    entry = startAnalysis(url, cacheKey)
    inFlight.set(cacheKey, entry)
  }

  const raw = await entry.fast
  const thresholds = riskThresholds ?? DEFAULT_THRESHOLDS
  const domainResult = analyzeDomain(url)

  const result = buildResult({ domainResult, raw, contentResult, thresholds })
  const stage = result.pending.length > 0 ? 'fast result' : 'complete'
  console.log(`Analysis ${stage}: ${url} → score ${result.score} (${result.riskLevel.label})`)

  if (result.pending.length === 0) return { result, final: null }

  const final = entry.finalRaw.then(finalRaw => {
    const finalResult = buildResult({ domainResult, raw: finalRaw, contentResult, thresholds })
    console.log(`Analysis complete: ${url} → score ${finalResult.score} (${finalResult.riskLevel.label})`)
    return finalResult
  })
  return { result, final }
}

export async function clearCacheForURL(url) {
  const cacheKey = getCacheKey(url)
  apiResultsCache.delete(cacheKey)
  inFlight.delete(cacheKey)

  await withCacheLock(async () => {
    const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
    delete persistentApiCache[cacheKey]
    await chrome.storage.local.set({ persistentApiCache })
  })
}