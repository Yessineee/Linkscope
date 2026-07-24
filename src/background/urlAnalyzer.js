/* global chrome */

import { analyzeDomain } from './domainAnalyzer.js'
import { checkGoogleSafeBrowsing } from './googleSafeBrowsing.js'
import { checkIPQualityScore } from './ipQualityScore.js'
import { checkVirusTotal } from './virusTotal.js'
import { calculateRiskScore, DEFAULT_THRESHOLDS } from './riskScorer.js'
import { getCacheKey, shouldSkipURL, isPrivateURL } from '../utils/urlUtils.js'

const apiResultsCache = new Map()

const pendingAnalyses = new Map()

const CACHE_TTL_MS = 24 * 60 * 60 * 1000 // 24 hours


export function clearAllApiCache() {
  apiResultsCache.clear()
}

async function getCachedApiResults(cacheKey) {
  const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
  const entry = persistentApiCache[cacheKey]
  if (!entry) return null
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) return null
  return entry.data
}

async function setCachedApiResults(cacheKey, data) {
  const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
  persistentApiCache[cacheKey] = { data, timestamp: Date.now() }

  // Cap the cache at 200 domains to avoid unbounded storage growth
  const keys = Object.keys(persistentApiCache)
  if (keys.length > 200) {
    const sorted = keys.sort((a, b) => persistentApiCache[a].timestamp - persistentApiCache[b].timestamp)
    delete persistentApiCache[sorted[0]]
  }

  await chrome.storage.local.set({ persistentApiCache })
}

export async function analyzeURL(url, contentResult = {}, { ignoreWhitelist = false } = {}) {
  if (shouldSkipURL(url) || isPrivateURL(url)) return null

  const cacheKey = getCacheKey(url)

  if (!pendingAnalyses.has(cacheKey)) {
    pendingAnalyses.set(cacheKey, fetchRawApiResults(url, cacheKey))
  }
  const rawDataPromise = pendingAnalyses.get(cacheKey)

  const [{ whitelist = [] }, { riskThresholds }, rawApiData] = await Promise.all([
    chrome.storage.local.get('whitelist'),
    chrome.storage.local.get('riskThresholds'),
    rawDataPromise,
  ])

  if (!ignoreWhitelist && whitelist.includes(cacheKey)) {
    console.log('Whitelisted:', cacheKey)
    return null
  }

  const thresholds = riskThresholds ?? DEFAULT_THRESHOLDS
  const { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt } = rawApiData
  const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
  result.dataFetchedAt = dataFetchedAt
  console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)
  return result
}


async function fetchRawApiResults(url, cacheKey) {
  const persisted = await getCachedApiResults(cacheKey)
  if (persisted) {
    console.log('Persistent cache hit:', cacheKey)
    pendingAnalyses.delete(cacheKey)
    return persisted
  }

  if (apiResultsCache.has(cacheKey)) {
    const cached = apiResultsCache.get(cacheKey)
    if (Date.now() - cached.dataFetchedAt <= CACHE_TTL_MS) {
      console.log('API cache hit:', cacheKey)
      pendingAnalyses.delete(cacheKey)
      return cached
    }
    apiResultsCache.delete(cacheKey)
  }

  console.log('Analyzing URL:', url)
  const domainResult = analyzeDomain(url)

  const [gsbSettled, ipqsSettled] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkIPQualityScore(url),
  ])

  const gsbResult = gsbSettled.status === 'fulfilled' ? gsbSettled.value : { isThreat: false, threatType: null, error: true }

  const ipqsResult = ipqsSettled.status === 'fulfilled' ? ipqsSettled.value : { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }

  // Preliminary score
  const preliminary = calculateRiskScore(domainResult, gsbResult, ipqsResult, null, {}, DEFAULT_THRESHOLDS)

  let vtResult = { isThreat: false, detectionCount: 0, engineCount: 0, error: false }
  if (preliminary.score <= 70) {
    vtResult = await checkVirusTotal(url)
  } else {
    console.log('Skipping VT - preliminary score already dangerous:', preliminary.score)
  }

  const dataFetchedAt = Date.now()
  const apiData = { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt }
  apiResultsCache.set(cacheKey, apiData)
  await setCachedApiResults(cacheKey, apiData)
  pendingAnalyses.delete(cacheKey)

  return apiData
}


export async function clearCacheForURL(url) {
  const cacheKey = getCacheKey(url)
  apiResultsCache.delete(cacheKey)
  pendingAnalyses.delete(cacheKey)

  const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
  delete persistentApiCache[cacheKey]
  await chrome.storage.local.set({ persistentApiCache })
}