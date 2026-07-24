/* global chrome */

const BASE_URL = 'https://www.virustotal.com/api/v3'

const DETECTION_THRESHOLD = 5


const EXISTING_REPORT_MAX_AGE_MS = 24 * 60 * 60 * 1000


function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
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
    const response = await fetch(`${BASE_URL}/urls/${urlId}`, { method: 'GET', headers })
    
    if (!response.ok) return null

    const data = await response.json()
    const attrs = data.data?.attributes
    if (!attrs?.stats || !attrs?.last_analysis_date) return null

    const ageMs = Date.now() - attrs.last_analysis_date * 1000
    if (ageMs > EXISTING_REPORT_MAX_AGE_MS) return null

    return attrs.stats
  } catch (err) {
    console.warn('VT existing-report lookup failed, submitting a fresh scan instead:', err)
    return null
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

    const existingStats = await fetchExistingReport(getVtUrlId(url), headers)
    if (existingStats) {
      console.log('VT: reusing existing report, skipping fresh submission')
      return scoreFromStats(existingStats)
    }

    const formData = new FormData()
    formData.append('url', url)

    const submitResponse = await fetch(`${BASE_URL}/urls`, {
      method: 'POST',
      headers,
      body: formData,
    })

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

    await delay(8000)

    let resultData = await fetchAnalysis(analysisId, headers)
    if (!resultData) {
      return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
    }

    if (resultData.data?.attributes?.status !== 'completed') {
      await delay(5000)
      resultData = await fetchAnalysis(analysisId, headers)
      if (!resultData) {
        return { isThreat: false, detectionCount: 0, engineCount: 0, error: true }
      }
    }

    if (resultData.data?.attributes?.status !== 'completed') {
      console.warn('VT: analysis still queued after retry, treating as inconclusive')
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
    { method: 'GET', headers }
  )

  if (!resultResponse.ok) {
    console.error('VT result error:', resultResponse.status)
    return null
  }

  return resultResponse.json()
}