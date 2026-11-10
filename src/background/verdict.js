import { calculateRiskScore, describeSignal } from './riskScorer.js'

export const CACHE_TTL_MS = 24 * 60 * 60 * 1000
export const INCOMPLETE_TTL_MS = 5 * 60 * 1000

export const VT_SKIP_ABOVE_SCORE = 70
export const VT_MIN_SCORE = 20

const LEVEL_RANK = { SAFE: 0, LOW: 1, SUSPICIOUS: 2, DANGEROUS: 3 }

export function failedSourcesOf(raw) {
  const failed = []
  if (raw.gsbResult?.error) failed.push('Google Safe Browsing')
  if (raw.ipqsResult?.error) failed.push('IPQualityScore')
  // Entries cached before progressive verdicts have no vtState; they are finished.
  const vtFinished = raw.vtState === undefined || raw.vtState === 'done'
  if (vtFinished && raw.vtResult?.error) {
    failed.push(raw.vtResult.rateLimited ? 'VirusTotal (rate limit reached)' : 'VirusTotal')
  }
  return failed
}

export function pendingSourcesOf(raw) {
  return raw.vtState === 'pending' ? ['VirusTotal'] : []
}

export function ttlFor(raw) {
  return failedSourcesOf(raw).length > 0 ? INCOMPLETE_TTL_MS : CACHE_TTL_MS
}

// VirusTotal is a second opinion: used when the fast sources already suspect something,
// or when both of them failed and there would otherwise be no outside check at all.
export function shouldQueryVirusTotal(preliminaryScore, failedFastSources = 0) {
  if (preliminaryScore > VT_SKIP_ABOVE_SCORE) return false
  return preliminaryScore > VT_MIN_SCORE || failedFastSources >= 2
}

export function hasEscalated(before, after) {
  const from = LEVEL_RANK[before]
  const to = LEVEL_RANK[after]
  return from !== undefined && to !== undefined && to > from
}

export function buildResult({ domainResult, raw, contentResult = {}, thresholds }) {
  const result = calculateRiskScore(
    domainResult, raw.gsbResult, raw.ipqsResult, raw.vtResult, contentResult, thresholds
  )
  const failedSources = failedSourcesOf(raw)

  result.dataFetchedAt = raw.dataFetchedAt
  result.failedSources = failedSources
  result.incomplete = failedSources.length > 0
  result.pending = pendingSourcesOf(raw)
  result.externalLookups = raw.lookups ?? 'sent'

  if (failedSources.length > 0) {
    const signal = { id: 'incomplete', points: 0, evidence: { failedSources } }
    result.signals.push(signal)
    result.reasons.push(describeSignal(signal))
  }

  return result
}


export function buildContentResult({ page, redirect, headers, isHttps }) {
  const p = page ?? {}
  const r = redirect ?? {}
  const h = headers ?? {}
  return {
    hasSuspiciousForm: p.hasSuspiciousForm === true,
    hasUrgencyLanguage: p.hasUrgencyLanguage === true,
    isHTTPS: isHttps,
    hasRedirectChain: r.hasRedirectChain === true,
    redirectCount: r.redirectCount,
    redirectChain: r.redirectChain,
    hasCSP: h.hasCSP,
    hasHSTS: h.hasHSTS,
    hasXFrameOptions: h.hasXFrameOptions,
    hasXContentTypeOptions: h.hasXContentTypeOptions,
  }
}