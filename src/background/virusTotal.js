/* global chrome */

const BASE_URL = 'https://www.virustotal.com/api/v3'

const DETECTION_THRESHOLD = 5


function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
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

    // Freshly-submitted URLs (ones VT hasn't scanned before) are often still
    // "queued" after the first wait. One bounded retry catches the common case
    // without risking reading incomplete stats as a false "safe" verdict.
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

    const detectionCount = (stats.malicious ?? 0) + (stats.suspicious ?? 0)
    const engineCount = Object.values(stats).reduce((sum, val) => sum + val, 0)
    const isThreat = detectionCount >= DETECTION_THRESHOLD

    return {
      isThreat,
      detectionCount,
      engineCount,
      error: false,
    }

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