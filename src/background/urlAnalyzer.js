/* global chrome */

import { analyzeDomain } from './domainAnalyzer.js'
import { checkGoogleSafeBrowsing } from './googleSafeBrowsing.js'
import { checkIPQualityScore } from './ipQualityScore.js'
import { checkVirusTotal } from './virusTotal.js'
import { calculateRiskScore, DEFAULT_THRESHOLDS } from './riskScorer.js'
import { buildResult, ttlFor, shouldQueryVirusTotal } from './verdict.js'
import { getCacheKey, shouldSkipURL, isPrivateURL } from '../utils/urlUtils.js'
import { lookupUrlFor } from '../core/lookupUrl.js'

const apiResultsCache = new Map()
// One entry per site being analyzed right now: { fast, finalRaw, settledRaw }.
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

// Store a finished result, unless a rescan or cache clear has replaced this analysis in the meantime.
function commit(cacheKey, entry, raw) {
  if (inFlight.get(cacheKey) !== entry) return Promise.resolve()
  apiResultsCache.set(cacheKey, raw)
  return setCachedApiResults(cacheKey, raw).catch(err => console.warn('Could not persist API cache:', err))
}

// Raw data for a page where nothing was sent to any outside service.
// 'off' = the local-only setting; 'skipped' = a page that is not worth (or not safe) to look up.
function noLookupsRaw(lookups) {
  return {
    gsbResult: { isThreat: false, threatType: null, error: false, skipped: true },
    ipqsResult: { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: false, skipped: true },
    vtResult: null,
    vtState: 'skipped',
    lookups,
    dataFetchedAt: Date.now(),
  }
}

async function runFastPhase(url, cacheKey, entry) {
  const { localOnly } = await chrome.storage.local.get('localOnly')
  const plan = lookupUrlFor(url)

  // These results are cheap to recompute and are deliberately not cached, so turning
  // the setting off (or a rule changing) takes effect on the very next visit.
  if (localOnly === true || !plan.send) {
    console.log('No external lookups for', cacheKey, localOnly === true ? '(local only)' : `(${plan.reason})`)
    const raw = noLookupsRaw(localOnly === true ? 'off' : 'skipped')
    entry.settledRaw = raw
    entry.finalRaw = Promise.resolve(raw)
    return raw
  }

  const cached = await readCache(cacheKey)
  if (cached) {
    console.log('Cache hit:', cacheKey)
    entry.settledRaw = cached
    entry.finalRaw = Promise.resolve(cached)
    return cached
  }

  console.log('Analyzing URL:', plan.url)
  const domainResult = analyzeDomain(url)

  // Only the reduced address in `plan.url` ever leaves the browser.
  const [gsbSettled, ipqsSettled] = await Promise.allSettled([
    checkGoogleSafeBrowsing(plan.url),
    checkIPQualityScore(plan.url),
  ])

  const gsbResult = gsbSettled.status === 'fulfilled'
    ? gsbSettled.value
    : { isThreat: false, threatType: null, error: true }

  const ipqsResult = ipqsSettled.status === 'fulfilled'
    ? ipqsSettled.value
    : { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }

  const preliminary = calculateRiskScore(domainResult, gsbResult, ipqsResult, null, {}, DEFAULT_THRESHOLDS)
  const failedFast = (gsbResult.error ? 1 : 0) + (ipqsResult.error ? 1 : 0)
  const dataFetchedAt = Date.now()

  if (!shouldQueryVirusTotal(preliminary.score, failedFast)) {
    console.log('Skipping VT for', cacheKey)
    const raw = { gsbResult, ipqsResult, vtResult: null, vtState: 'skipped', dataFetchedAt }
    entry.settledRaw = raw
    entry.finalRaw = commit(cacheKey, entry, raw).then(() => raw)
    return raw
  }

  // VirusTotal runs in the background; the fast result is returned right away.
  const fastRaw = { gsbResult, ipqsResult, vtResult: null, vtState: 'pending', dataFetchedAt }
  entry.finalRaw = checkVirusTotal(plan.url)
    .catch(() => ({ isThreat: false, detectionCount: 0, engineCount: 0, error: true }))
    .then(vtResult => {
      const raw = { ...fastRaw, vtResult, vtState: 'done' }
      entry.settledRaw = raw
      return commit(cacheKey, entry, raw).then(() => raw)
    })
  return fastRaw
}

function startAnalysis(url, cacheKey) {
  const entry = { fast: null, finalRaw: null, settledRaw: null }
  entry.fast = runFastPhase(url, cacheKey, entry)
  entry.fast
    .then(() => entry.finalRaw)
    .catch(() => {})
    .finally(() => {
      if (inFlight.get(cacheKey) === entry) inFlight.delete(cacheKey)
    })
  return entry
}

// Gathers the raw data for a URL (from cache, or from the sources) without scoring it.
// Returns null when the URL is skipped or whitelisted. Otherwise { raw, final }:
// `raw` is ready after the fast sources; `final` is null when nothing is pending,
// or a promise for the complete raw data once VirusTotal has finished.
export async function collectRaw(url, { ignoreWhitelist = false } = {}) {
  if (shouldSkipURL(url) || isPrivateURL(url)) return null

  const cacheKey = getCacheKey(url)

  // The whitelist is read BEFORE anything is sent anywhere, so a whitelisted site never reaches the APIs.
  const { whitelist = [] } = await chrome.storage.local.get('whitelist')
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

  const fastRaw = await entry.fast
  if (entry.settledRaw) return { raw: entry.settledRaw, final: null }
  return { raw: fastRaw, final: entry.finalRaw }
}

// Scored version of collectRaw, used by the right-click link check.
export async function analyzeURL(url, contentResult = {}, options = {}) {
  const collected = await collectRaw(url, options)
  if (!collected) return null

  const { riskThresholds } = await chrome.storage.local.get('riskThresholds')
  const thresholds = riskThresholds ?? DEFAULT_THRESHOLDS
  const domainResult = analyzeDomain(url)
  const build = raw => buildResult({ domainResult, raw, contentResult, thresholds })

  const result = build(collected.raw)
  const final = collected.final ? collected.final.then(build) : null
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