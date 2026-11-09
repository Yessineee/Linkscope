/* global chrome */

const ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

const REQUEST_TIMEOUT_MS = 10_000


const THREAT_TYPES = [
  'MALWARE',
  'SOCIAL_ENGINEERING',
  'UNWANTED_SOFTWARE',
  'POTENTIALLY_HARMFUL_APPLICATION',
]

export async function checkGoogleSafeBrowsing(url) {
  try {
    const { apiKeys = {} } = await chrome.storage.local.get('apiKeys')
    const API_KEY = apiKeys.gsb
    if (!API_KEY) {
      console.warn('GSB API key not configured')
      return { isThreat: false, threatType: null, error: true }
    }
    const response = await fetch(`${ENDPOINT}?key=${encodeURIComponent(API_KEY)}`, {
      method: 'POST',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: {
          clientId: 'linkscope',
          clientVersion: '1.0.0',
        },
        threatInfo: {
          threatTypes: THREAT_TYPES,
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }),
    })

    if (!response.ok) {
      console.error('GSB API error:', response.status)
      return { isThreat: false, threatType: null, error: true }
    }

    const data = await response.json()
    const isThreat = !!(data.matches && data.matches.length > 0)
    const threatType = isThreat ? data.matches[0].threatType : null

    return { isThreat, threatType, error: false }

  } catch (err) {
    console.error(err.name === 'TimeoutError' ? 'GSB request timed out' : 'GSB fetch failed:', err)
    return { isThreat: false, threatType: null, error: true }
  }
}