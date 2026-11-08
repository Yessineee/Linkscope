import test from 'node:test'
import assert from 'node:assert/strict'
import { calculateRiskScore, describeSignal } from '../src/background/riskScorer.js'

function score({ domain = null, gsb = null, ipqs = null, vt = null, content = {}, thresholds } = {}) {
  return calculateRiskScore(domain, gsb, ipqs, vt, content, thresholds)
}
const ids = r => r.signals.map(s => s.id)

test('a clean page scores 0 with no signals', () => {
  const r = score()
  assert.equal(r.score, 0)
  assert.equal(r.riskLevel.label, 'SAFE')
  assert.deepEqual(r.signals, [])
  assert.deepEqual(r.reasons, [])
})

test('a Google Safe Browsing match is worth 80', () => {
  const r = score({ gsb: { isThreat: true, threatType: 'SOCIAL_ENGINEERING' } })
  assert.equal(r.score, 80)
  assert.deepEqual(ids(r), ['gsb_match'])
  assert.equal(r.riskLevel.label, 'DANGEROUS')
})

test('IPQualityScore counts once, with phishing taking precedence', () => {
  const r = score({ ipqs: { isPhishing: true, isMalware: true, fraudScore: 99, domainAge: '2 days ago' } })
  assert.equal(r.score, 60)
  assert.deepEqual(ids(r), ['ipqs_phishing'])
})

test('an IPQualityScore risk score must be above 75 to count', () => {
  assert.equal(score({ ipqs: { fraudScore: 75 } }).score, 0)
  assert.deepEqual(ids(score({ ipqs: { fraudScore: 76 } })), ['ipqs_high_risk'])
})

test('VirusTotal detections are worth 50 and keep their counts', () => {
  const r = score({ vt: { isThreat: true, detectionCount: 7, engineCount: 70 } })
  assert.equal(r.score, 50)
  assert.deepEqual(r.signals[0].evidence, { detectionCount: 7, engineCount: 70 })
})

test('a lookalike signal carries the brand and the kind', () => {
  const r = score({ domain: { isLookalike: true, matchedBrand: 'paypal', kind: 'wrong-domain' } })
  assert.equal(r.score, 40)
  assert.deepEqual(r.signals[0].evidence, { brand: 'paypal', kind: 'wrong-domain' })
})

test('only typosquats are described as typosquatting', () => {
  const text = kind => score({ domain: { isLookalike: true, matchedBrand: 'paypal', kind } }).reasons[0]
  assert.ok(text('typosquat').includes('typosquatting'))
  for (const kind of ['wrong-domain', 'brand-in-subdomain', 'combosquat']) {
    assert.ok(!text(kind).includes('typosquatting'), kind)
  }
  assert.notEqual(text('wrong-domain'), text('combosquat'))
})

test('mixed script is its own signal and stacks with a lookalike', () => {
  const r = score({ domain: { isLookalike: true, matchedBrand: 'apple', kind: 'typosquat', hasMixedScript: true } })
  assert.equal(r.score, 80)
  assert.deepEqual(ids(r), ['domain_lookalike', 'domain_mixed_script'])
})

test('page signals have their own weights', () => {
  assert.equal(score({ content: { hasSuspiciousForm: true } }).score, 30)
  assert.equal(score({ content: { hasRedirectChain: true } }).score, 25)
  assert.equal(score({ content: { isHTTPS: false } }).score, 20)
  assert.equal(score({ content: { hasUrgencyLanguage: true } }).score, 15)
})

test('missing HTTPS and headers only count when explicitly false', () => {
  assert.equal(score({ content: {} }).score, 0)
  assert.equal(score({ content: { isHTTPS: undefined, hasCSP: undefined } }).score, 0)
  assert.equal(score({ content: { hasCSP: false } }).score, 5)
  assert.equal(score({ content: { hasCSP: false, hasHSTS: false } }).score, 10)
})

test('failed lookups add nothing to the score', () => {
  const r = score({
    gsb: { isThreat: false, threatType: null, error: true },
    ipqs: { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: true },
    vt: { isThreat: false, detectionCount: 0, engineCount: 0, error: true, rateLimited: true },
  })
  assert.equal(r.score, 0)
  assert.deepEqual(r.signals, [])
})

test('the score is capped at 100', () => {
  const r = score({
    gsb: { isThreat: true, threatType: 'MALWARE' },
    ipqs: { isPhishing: true, fraudScore: 90 },
    vt: { isThreat: true, detectionCount: 9, engineCount: 70 },
  })
  assert.equal(r.score, 100)
})

test('thresholds decide the risk level', () => {
  const content = { hasSuspiciousForm: true }
  assert.equal(score({ content }).riskLevel.label, 'LOW')
  assert.equal(
    score({ content, thresholds: { low: 10, suspicious: 20, dangerous: 25 } }).riskLevel.label,
    'DANGEROUS'
  )
})

test('reasons are the text of the signals, in the same order', () => {
  const r = score({
    gsb: { isThreat: true, threatType: 'MALWARE' },
    content: { isHTTPS: false, hasUrgencyLanguage: true },
  })
  assert.equal(r.reasons.length, r.signals.length)
  r.signals.forEach((s, i) => assert.equal(r.reasons[i], describeSignal(s)))
})

test('the incomplete-result note is described like any other signal', () => {
  const text = describeSignal({
    id: 'incomplete',
    points: 0,
    evidence: { failedSources: ['VirusTotal (rate limit reached)'] },
  })
  assert.ok(text.includes('VirusTotal (rate limit reached)'))
})