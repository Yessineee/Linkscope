/* global chrome */

const ENDPOINT = 'https://www.ipqualityscore.com/api/json/url'

const REQUEST_TIMEOUT_MS = 10_000

export async function checkIPQualityScore(url) {
  try {
    const { apiKeys = {} } = await chrome.storage.local.get('apiKeys')
    const API_KEY = apiKeys.ipqs
    if (!API_KEY) {
      console.warn('IPQS API key not configured')
      return { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }
    }
    const encodedURL = encodeURIComponent(url)

    const response = await fetch(
      `${ENDPOINT}/${encodeURIComponent(API_KEY)}/${encodedURL}?strictness=1&allow_public_access_points=true`,
       { method: 'GET', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) }
    )

    if (!response.ok) {
      console.error('IPQS API error:', response.status)
      return { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }
    }

    const data = await response.json()

    if (!data.success) {
      console.error('IPQS error message:', data.message)
      return { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }
    }

    const fraudScore = data.risk_score ?? 0
    const isPhishing = data.phishing === true
    const isMalware = data.malware === true
    const isThreat = isPhishing || isMalware || fraudScore > 75
    const domainAge = data.domain_age?.human ?? null

    return {
      isThreat,
      fraudScore,
      isPhishing,
      isMalware,
      domainAge,
      error: false,
    }

  } catch (err) {
    console.error(err.name === 'TimeoutError' ? 'IPQS request timed out' : 'IPQS fetch failed:', err)
    return { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true }
  }
}