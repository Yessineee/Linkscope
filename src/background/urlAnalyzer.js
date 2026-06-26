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

export async function analyzeURL(url, contentResult = {}) {
  if (shouldSkipURL(url) || isPrivateURL(url)) return null

  const { whitelist = [] } = await chrome.storage.local.get('whitelist')
  const hostname = getCacheKey(url)
  if (whitelist.includes(hostname)) {
    console.log('Whitelisted:', hostname)
    return null
  }

  const { riskThresholds } = await chrome.storage.local.get('riskThresholds')
  const thresholds = riskThresholds ?? DEFAULT_THRESHOLDS

  const cacheKey = getCacheKey(url)

  const persisted = await getCachedApiResults(cacheKey)
  if (persisted) {
    console.log('Persistent cache hit:', cacheKey)
    const { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt } = persisted
    const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
    result.dataFetchedAt = dataFetchedAt
    console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)
    return result
  }

  if (apiResultsCache.has(cacheKey)) {
    console.log('API cache hit — recalculating with content results:', cacheKey)
    const { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt } = apiResultsCache.get(cacheKey)
    const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
    result.dataFetchedAt = dataFetchedAt
    console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)
    return result
  }

  if (pendingAnalyses.has(cacheKey)) {
    console.log('Waiting for in-flight analysis:', cacheKey)
    await pendingAnalyses.get(cacheKey)

    if (apiResultsCache.has(cacheKey)) {
      const { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt } = apiResultsCache.get(cacheKey)
      const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
      result.dataFetchedAt = dataFetchedAt
      console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)
      return result
    }
  }

  const analysisPromise = runAnalysis(url, contentResult, cacheKey, thresholds)
  pendingAnalyses.set(cacheKey, analysisPromise)

  const result = await analysisPromise
  pendingAnalyses.delete(cacheKey)
  return result
}

async function runAnalysis(url, contentResult, cacheKey, thresholds) {
  console.log('Analyzing URL:', url)

  const domainResult = analyzeDomain(url)

  const [gsbSettled, ipqsSettled] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkIPQualityScore(url),
  ])

  const gsbResult = gsbSettled.status === 'fulfilled' ? gsbSettled.value : { isThreat: false, threatType: null, error: true }

  const ipqsResult = ipqsSettled.status === 'fulfilled' ? ipqsSettled.value : { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }

  const preliminary = calculateRiskScore(domainResult, gsbResult, ipqsResult, null, contentResult, thresholds)

  let vtResult = { isThreat: false, detectionCount: 0, engineCount: 0, error: false }
  if (preliminary.score <= 70) {
    vtResult = await checkVirusTotal(url)
  } else {
    console.log('Skipping VT — preliminary score already dangerous:', preliminary.score)
  }

  const dataFetchedAt = Date.now()
  const apiData = { domainResult, gsbResult, ipqsResult, vtResult, dataFetchedAt }
  apiResultsCache.set(cacheKey, apiData)
  await setCachedApiResults(cacheKey, apiData)

  const result = calculateRiskScore(domainResult, gsbResult, ipqsResult, vtResult, contentResult, thresholds)
  result.dataFetchedAt = dataFetchedAt

  console.log(`Analysis complete: ${url} → score ${result.score} (${result.riskLevel.label})`)

  return result
}


export async function clearCacheForURL(url) {
  const cacheKey = getCacheKey(url)
  apiResultsCache.delete(cacheKey)
  pendingAnalyses.delete(cacheKey)

  const { persistentApiCache = {} } = await chrome.storage.local.get('persistentApiCache')
  delete persistentApiCache[cacheKey]
  await chrome.storage.local.set({ persistentApiCache })
}