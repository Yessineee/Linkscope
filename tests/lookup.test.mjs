import test from 'node:test'
import assert from 'node:assert/strict'
import { lookupUrlFor } from '../src/core/lookupUrl.js'

test('query string and fragment are never sent', () => {
  const r = lookupUrlFor('https://example.com/page?token=abc#frag')
  assert.equal(r.send, true)
  assert.equal(r.url, 'https://example.com/page')
})

test('credentials in the address are dropped', () => {
  assert.equal(lookupUrlFor('https://user:pass@example.com/x').url, 'https://example.com/x')
})

test('the port is kept', () => {
  assert.equal(lookupUrlFor('http://example.com:8080/x?y=1').url, 'http://example.com:8080/x')
})

test('a trailing-dot hostname is normalized', () => {
  assert.equal(lookupUrlFor('https://example.com./x').url, 'https://example.com/x')
})

test('first-party pages of big brands are not sent anywhere', () => {
  for (const url of [
    'https://mail.google.com/mail/u/0/#inbox',
    'https://docs.google.com/document/d/1n3fEaxRQU11Z5NMQ7N2mjWVDJ0Zsynvf9qMRaVu_gq4/edit',
    'https://www.facebook.com/',
    'https://github.com/user/private-repo',
    'https://www.amazon.fr/dp/B000000000',
  ]) {
    const r = lookupUrlFor(url)
    assert.equal(r.send, false, url)
    assert.equal(r.reason, 'brand-owned', url)
  }
})

test('lookalikes and shared-host impersonation are still sent', () => {
  assert.equal(lookupUrlFor('https://paypa1.com/login').send, true)
  assert.equal(lookupUrlFor('https://google.xyz/').send, true)
  assert.equal(lookupUrlFor('https://paypal.github.io/login?x=1').url, 'https://paypal.github.io/login')
})

test('hosts that publish other people\'s pages are still checked', () => {
  assert.equal(lookupUrlFor('https://evil.wordpress.com/login').send, true)
  assert.equal(lookupUrlFor('https://www.canva.com/design/AAA/view').send, true)
  assert.equal(lookupUrlFor('https://wetransfer.com/downloads/abc').send, true)
})

test('multi-tenant hosts keep their whole path, even long IDs', () => {
  const id = '1FAIpQLSdAbCdEfGhIjKlMnOpQrStUvWxYz0123456789'
  const r = lookupUrlFor(`https://docs.google.com/forms/d/e/${id}/viewform?usp=sf_link`)
  assert.equal(r.send, true)
  assert.equal(r.url, `https://docs.google.com/forms/d/e/${id}/viewform`)
})

test('owner areas and editor pages on multi-tenant hosts are not sent', () => {
  for (const url of [
    'https://sites.google.com/u/0/?pli=1',
    'https://sites.google.com/u/0/d/ABC/edit?ntd=1',
    'https://docs.google.com/forms/d/ABC/edit',
  ]) {
    const r = lookupUrlFor(url)
    assert.equal(r.send, false, url)
    assert.equal(r.reason, 'owner-area', url)
  }
  assert.equal(lookupUrlFor('https://sites.google.com/view/mysite').send, true)
})

test('the path is cut at the first secret-looking segment', () => {
  const cases = {
    'https://example.com/document/d/1n3fEaxRQU11Z5NMQ7N2mjWVDJ0Zsynvf9qMRaVu_gq4/edit': 'https://example.com/document/d',
    'https://example.com/reset/123e4567-e89b-12d3-a456-426614174000/confirm': 'https://example.com/reset',
    'https://example.com/files/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08': 'https://example.com/files',
    'https://example.com/auth/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c/x': 'https://example.com/auth',
  }
  for (const [input, expected] of Object.entries(cases)) {
    assert.equal(lookupUrlFor(input).url, expected, input)
  }
})

test('readable slugs and short IDs are kept', () => {
  for (const url of [
    'https://example.com/blog/how-to-secure-your-home-network-guide',
    'https://example.com/blog/best-laptops-of-2026-reviewed-by-experts',
    'https://example.com/watch/12345',
  ]) {
    assert.equal(lookupUrlFor(url).url, url)
  }
})

test('a secret in the first segment leaves only the root', () => {
  assert.equal(lookupUrlFor('https://example.com/123e4567-e89b-12d3-a456-426614174000/x').url, 'https://example.com/')
})

test('addresses that are not web pages are never sent', () => {
  const r = lookupUrlFor('chrome://extensions')
  assert.equal(r.send, false)
  assert.equal(r.reason, 'invalid')
})

test('public IP addresses are sent without their query', () => {
  assert.equal(lookupUrlFor('http://203.0.113.5/x?a=1').url, 'http://203.0.113.5/x')
})

test('country variants of big brands count as first-party, shared hosts and odd suffixes do not', () => {
  assert.equal(lookupUrlFor('https://www.google.fr/search?q=x').send, false)
  assert.equal(lookupUrlFor('https://www.amazon.co.uk/dp/B000000000').send, false)
  assert.equal(lookupUrlFor('https://google.github.io/').send, true)
  assert.equal(lookupUrlFor('https://google.xyz/').send, true)
})