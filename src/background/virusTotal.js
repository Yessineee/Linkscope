/* global chrome */

const BASE_URL = 'https://www.virustotal.com/api/v3'

const REQUEST_TIMEOUT_MS = 15_000

const DETECTION_THRESHOLD = 5


const EXISTING_REPORT_MAX_AGE_MS = 24 * 60 * 60 * 1000


function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

const WINDOW_MS = 60_000
const MAX_CALLS_PER_WINDOW = 4 // free tier: 4 lookups per minute
const recentCalls = []

function reserveVtSlot() {
  const now = Date.now()
  while (recentCalls.length && now - recentCalls[0] >= WINDOW_MS) recentCalls.shift()
  if (recentCalls.length >= MAX_CALLS_PER_WINDOW) return false
  recentCalls.push(now)
  return true
}

function rateLimited() {
  return { isThreat: false, detectionCount: 0, engineCount: 0, error: true, rateLimited: true }
}


function getVtUrlId(url) {
  return btoa(url).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function scoreFromStats(stats) {
  const detectionCount = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
  const engineCount = Object.values(stats).reduce((sum, val) => sum + val, 0)
  const isThreat = detectionCount >= DETECTION_THRESHOLD

  return { isThreat, detectionCount, engineCount, error: false }
}

async function fetchExistingReport(urlId, headers) {
  try {
    const response = await fetch(`${BASE_URL}/urls/${urlId}`, { method: 'GET', headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) })

    if (response.status === 429) return { rateLimited: true }
    if (!response.ok) return { stats: null }

    const data = await response.json()
    const attrs = data.data?.attributes
    if (!attrs?.stats || !attrs?.last_analysis_date) return { stats: null }

    const ageMs = Date.now() - attrs.last_analysis_date * 1000
    if (ageMs > EXISTING_REPORT_MAX_AGE_MS) return { stats: null }

    return { stats: attrs.stats }
  } catch (err) {
    console.warn('VT existing-report lookup failed, submitting a fresh scan instead:', err)
    return { stats: null }
  }
}

export async function checkVirusTotal(url) {
  try {
    const { apiKeys = {} } = await chrome.storage.local.get('apiKeys')
    const API_KEY = apiKeys.vt
    if (!API_KEY) {
      console.warn('VT API key not configured')
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    const headers = { 'x-apikey': API_KEY }

    if (!reserveVtSlot()) return rateLimited()
    const existing = await fetchExistingReport(getVtUrlId(url), headers)
    if (existing.rateLimited) return rateLimited()
    if (existing.stats) {
      console.log('VT: reusing existing report, skipping fresh submission')
      return scoreFromStats(existing.stats)
    }

    if (!reserveVtSlot()) return rateLimited()
    const formData = new FormData()
    formData.append('url', url)

    const submitResponse = await fetch(`${BASE_URL}/urls`, {
      method: 'POST',
      headers,
      body: formData,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    })

    if (submitResponse.status === 429) return rateLimited()
    if (!submitResponse.ok) {
      console.error('VT submit error:', submitResponse.status)
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    const submitData = await submitResponse.json()
    const analysisId = submitData.data?.id

    if (!analysisId) {
      console.error('VT: no analysis ID returned')
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    const POLL_DELAYS_MS = [6000, 6000, 8000, 10000] // about 30 s in total
    
    let resultData = null
    for (const wait of POLL_DELAYS_MS) {
      await delay(wait)
      resultData = await fetchAnalysis(analysisId, headers)
      if (!resultData) {
        return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
      }
      if (resultData.data?.attributes?.status === 'completed') break
    }

    if (resultData?.data?.attributes?.status !== 'completed') {
      console.warn('VT: analysis still queued after ~30 s, treating as inconclusive')
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    const stats = resultData.data?.attributes?.stats

    if (!stats) {
      console.error('VT: no stats in response')
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    return scoreFromStats(stats)

  } catch (err) {
    console.error('VT fetch failed:', err)
    return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
  }
}

async function fetchAnalysis(analysisId, headers) {
  const resultResponse = await fetch(
    `${BASE_URL}/analyses/${analysisId}`,
    { method: 'GET', headers, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }
  )

  if (!resultResponse.ok) {
    console.error('VT result error:', resultResponse.status)
    return null
  }

  return resultResponse.json()
}