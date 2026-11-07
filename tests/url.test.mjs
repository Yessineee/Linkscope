import test from 'node:test'
import assert from 'node:assert/strict'
import { parseUrl } from '../src/core/url.js'

test('only http and https are accepted', () => {
  assert.equal(parseUrl('chrome://extensions'), null)
  assert.equal(parseUrl('javascript:alert(1)'), null)
  assert.equal(parseUrl('ftp://example.com'), null)
  assert.equal(parseUrl('not a url'), null)
})

test('trailing dot is normalized away', () => {
  const r = parseUrl('https://paypa1.com./login')
  assert.equal(r.hostname, 'paypa1.com')
  assert.equal(r.registrableDomain, 'paypa1.com')
})

test('multi-part public suffix is handled', () => {
  const r = parseUrl('https://bank.com.ng/')
  assert.equal(r.registrableDomain, 'bank.com.ng')
  assert.equal(r.domainLabel, 'bank')
})

test('shared hosts expose the owner-chosen label', () => {
  const r = parseUrl('https://paypal.github.io/')
  assert.equal(r.registrableDomain, 'paypal.github.io')
  assert.equal(r.domainLabel, 'paypal')
  assert.equal(r.onSharedHost, true)
})

test('subdomain labels are split out', () => {
  const r = parseUrl('https://a.b.paypal.evil.com/')
  assert.equal(r.registrableDomain, 'evil.com')
  assert.deepEqual(r.subdomainLabels, ['a', 'b', 'paypal'])
})

test('private network detection is numeric and only for real IPs', () => {
  assert.equal(parseUrl('http://10.paypal-login.com/').isPrivateNetwork, false)
  assert.equal(parseUrl('http://10.1.2.3/').isPrivateNetwork, true)
  assert.equal(parseUrl('http://172.16.0.1/').isPrivateNetwork, true)
  assert.equal(parseUrl('http://172.32.0.1/').isPrivateNetwork, false)
  assert.equal(parseUrl('http://[::1]/').isPrivateNetwork, true)
  assert.equal(parseUrl('http://localhost:3000/').isPrivateNetwork, true)
})