import { analyzeDomain } from '../../src/background/domainAnalyzer.js'
import { calculateRiskScore } from '../../src/background/riskScorer.js'
import { isHTTPS } from '../../src/utils/domainUtils.js'

export function scoreUrl(url) {
  const domain = analyzeDomain(url)
  const result = calculateRiskScore(domain, null, null, null, { isHTTPS: isHTTPS(url) })
  return {
    score: result.score,
    level: result.riskLevel.label,
    signals: result.signals.map(signal => signal.id),
    kind: domain.kind ?? 'none',
    brand: domain.matchedBrand ?? null,
  }
}