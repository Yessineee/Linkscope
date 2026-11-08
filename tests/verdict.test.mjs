import test from 'node:test'
import assert from 'node:assert/strict'
import { buildResult, failedSourcesOf, pendingSourcesOf, ttlFor, shouldQueryVirusTotal, hasEscalated, CACHE_TTL_MS, INCOMPLETE_TTL_MS } from '../src/background/verdict.js'

const gsbOk = { isThreat: false, threatType: null, error: false }
const ipqsOk = { isThreat: false, fraudScore: 0, isPhishing: false, isMalware: false, domainAge: null, error: false }
const vtClean = { isThreat: false, detectionCount: 0, engineCount: 70, error: false }
const vtBad = { isThreat: true, detectionCount: 12, engineCount: 70, error: false }
const vtRateLimited = { isThreat: false, detectionCount: 0, engineCount: 0, error: true, rateLimited: true }

function raw(overrides = {}) {
  return { gsbResult: gsbOk, ipqsResult: ipqsOk, vtResult: null, vtState: 'pending', dataFetchedAt: 1000, ...overrides }
}

test('VirusTotal is pending only while it is running', () => {
  assert.deepEqual(pendingSourcesOf(raw()), ['VirusTotal'])
  assert.deepEqual(pendingSourcesOf(raw({ vtState: 'done', vtResult: vtClean })), [])
  assert.deepEqual(pendingSourcesOf(raw({ vtState: 'skipped' })), [])
})

test('entries cached before this change count as finished', () => {
  const legacy = { gsbResult: gsbOk, ipqsResult: ipqsOk, vtResult: vtClean, dataFetchedAt: 1 }
  assert.deepEqual(pendingSourcesOf(legacy), [])
  assert.deepEqual(failedSourcesOf(legacy), [])
})

test('a lookup that has not finished is not a failure', () => {
  assert.deepEqual(failedSourcesOf(raw()), [])
})

test('a skipped VirusTotal lookup is not a failure either', () => {
  assert.deepEqual(failedSourcesOf(raw({ vtState: 'skipped', vtResult: null })), [])
})

test('failed sources are named, including the rate limit', () => {
  const failed = failedSourcesOf(raw({
    gsbResult: { ...gsbOk, error: true },
    ipqsResult: { ...ipqsOk, error: true },
    vtState: 'done',
    vtResult: vtRateLimited,
  }))
  assert.deepEqual(failed, ['Google Safe Browsing', 'IPQualityScore', 'VirusTotal (rate limit reached)'])
})

test('complete results are cached for 24 hours, incomplete ones for 5 minutes', () => {
  assert.equal(ttlFor(raw({ vtState: 'done', vtResult: vtClean })), CACHE_TTL_MS)
  assert.equal(ttlFor(raw({ vtState: 'skipped', gsbResult: { ...gsbOk, error: true } })), INCOMPLETE_TTL_MS)
})

test('VirusTotal is skipped for dangerous previews and bare brand hosts', () => {
  assert.equal(shouldQueryVirusTotal(0, false), true)
  assert.equal(shouldQueryVirusTotal(70, false), true)
  assert.equal(shouldQueryVirusTotal(71, false), false)
  assert.equal(shouldQueryVirusTotal(0, true), false)
})

test('while VirusTotal runs, the result is built without it and says what is pending', () => {
  const r = buildResult({ domainResult: null, raw: raw() })
  assert.equal(r.score, 0)
  assert.deepEqual(r.pending, ['VirusTotal'])
  assert.equal(r.incomplete, false)
  assert.equal(r.dataFetchedAt, 1000)
})

test('pending adds no signal and no reason', () => {
  const r = buildResult({ domainResult: null, raw: raw() })
  assert.deepEqual(r.signals, [])
  assert.deepEqual(r.reasons, [])
})

test('the final result includes the VirusTotal detections', () => {
  const r = buildResult({ domainResult: null, raw: raw({ vtState: 'done', vtResult: vtBad }) })
  assert.equal(r.score, 50)
  assert.deepEqual(r.pending, [])
  assert.equal(r.signals[0].id, 'vt_detections')
})

test('VirusTotal can only raise the verdict, never lower it', () => {
  const phishing = { ...ipqsOk, isPhishing: true, fraudScore: 90 }
  const fast = buildResult({ domainResult: null, raw: raw({ ipqsResult: phishing }) })
  const final = buildResult({ domainResult: null, raw: raw({ ipqsResult: phishing, vtState: 'done', vtResult: vtBad }) })
  assert.equal(fast.riskLevel.label, 'SUSPICIOUS')
  assert.equal(final.riskLevel.label, 'DANGEROUS')
  assert.ok(final.score >= fast.score)
  assert.equal(hasEscalated(fast.riskLevel.label, final.riskLevel.label), true)
})

test('a failed source adds an incomplete note without changing the score', () => {
  const r = buildResult({ domainResult: null, raw: raw({ vtState: 'done', vtResult: vtRateLimited }) })
  assert.equal(r.score, 0)
  assert.equal(r.incomplete, true)
  assert.deepEqual(r.failedSources, ['VirusTotal (rate limit reached)'])
  assert.equal(r.signals.at(-1).id, 'incomplete')
  assert.ok(r.reasons.at(-1).includes('rate limit'))
})

test('only a higher risk level counts as an escalation', () => {
  assert.equal(hasEscalated('SAFE', 'DANGEROUS'), true)
  assert.equal(hasEscalated('LOW', 'SUSPICIOUS'), true)
  assert.equal(hasEscalated('SUSPICIOUS', 'SUSPICIOUS'), false)
  assert.equal(hasEscalated('DANGEROUS', 'SUSPICIOUS'), false)
  assert.equal(hasEscalated('SAFE', 'unknown'), false)
})

test('page signals pass through to the result', () => {
  const r = buildResult({ domainResult: null, raw: raw(), contentResult: { hasSuspiciousForm: true } })
  assert.equal(r.score, 30)
  assert.deepEqual(r.signals.map(s => s.id), ['suspicious_form'])
})