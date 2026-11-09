import test from 'node:test'
import assert from 'node:assert/strict'
import { buildContentResult } from '../src/background/verdict.js'

test('only strict booleans from the page count as signals', () => {
  const loose = buildContentResult({ page: { hasSuspiciousForm: 'true', hasUrgencyLanguage: 1 }, isHttps: true })
  assert.equal(loose.hasSuspiciousForm, false)
  assert.equal(loose.hasUrgencyLanguage, false)
  const strict = buildContentResult({ page: { hasSuspiciousForm: true, hasUrgencyLanguage: true }, isHttps: true })
  assert.equal(strict.hasSuspiciousForm, true)
  assert.equal(strict.hasUrgencyLanguage, true)
})

test('the page cannot override HTTPS, headers or redirect data', () => {
  const r = buildContentResult({
    page: { isHTTPS: false, hasCSP: false, hasRedirectChain: true, extra: 'x' },
    isHttps: true,
  })
  assert.equal(r.isHTTPS, true)
  assert.equal(r.hasCSP, undefined)
  assert.equal(r.hasRedirectChain, false)
  assert.equal('extra' in r, false)
})

test('headers and redirect data come from their own sources', () => {
  const r = buildContentResult({
    headers: { hasCSP: false, hasHSTS: true },
    redirect: { hasRedirectChain: true, redirectCount: 3, redirectChain: ['a', 'b', 'c'] },
    isHttps: false,
  })
  assert.equal(r.isHTTPS, false)
  assert.equal(r.hasCSP, false)
  assert.equal(r.hasHSTS, true)
  assert.equal(r.hasRedirectChain, true)
  assert.equal(r.redirectCount, 3)
})

test('missing or null inputs do not throw', () => {
  const r = buildContentResult({ page: null, redirect: null, headers: null, isHttps: true })
  assert.equal(r.hasSuspiciousForm, false)
  assert.equal(r.hasRedirectChain, false)
  assert.equal(r.hasCSP, undefined)
})