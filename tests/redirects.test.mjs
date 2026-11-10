import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeRedirectChain } from '../src/core/redirects.js'

const analyze = (...urls) => analyzeRedirectChain(urls)

test('a normal page load is one hop and not flagged', () => {
  const r = analyze('https://one-site.com/')
  assert.equal(r.redirectCount, 1)
  assert.equal(r.hasRedirectChain, false)
})

test('redirects between the sites of one brand are not suspicious', () => {
  const r = analyze('https://www.google.com/', 'https://accounts.google.com/', 'https://www.youtube.com/', 'https://mail.google.com/')
  assert.equal(r.redirectCount, 4)
  assert.equal(r.hasRedirectChain, false)
})

test('link shorteners are not counted as untrusted hops', () => {
  assert.equal(analyze('https://bit.ly/abc', 'https://t.co/xyz', 'https://one-site.com/').hasRedirectChain, false)
})

test('a chain through three unrelated domains is flagged', () => {
  assert.equal(analyze('https://one-site.com/', 'https://two-site.net/', 'https://three-site.org/').hasRedirectChain, true)
})

test('two unrelated domains are not enough', () => {
  assert.equal(analyze('https://one-site.com/', 'https://two-site.net/').hasRedirectChain, false)
})

test('many hops on a single domain are not a chain', () => {
  assert.equal(analyze('https://one-site.com/login', 'https://one-site.com/auth', 'https://one-site.com/home').hasRedirectChain, false)
})

test('a brand name on the wrong domain is not a trusted hop', () => {
  assert.equal(analyze('https://one-site.com/', 'https://paypal.xyz/', 'https://two-site.net/').hasRedirectChain, true)
})

test('hosting platforms are not trusted because of their name', () => {
  assert.equal(analyze('https://one-site.com/', 'https://someone.github.io/', 'https://two-site.net/').hasRedirectChain, true)
})

test('sites where anyone can publish a page are not trusted', () => {
  assert.equal(analyze('https://one-site.com/', 'https://someone.wordpress.com/', 'https://two-site.net/').hasRedirectChain, true)
})

test('hops that are not web pages are ignored', () => {
  assert.equal(analyze('chrome://newtab/', 'https://one-site.com/').redirectCount, 1)
})

test('repeated hops and fragments do not add to the chain', () => {
  assert.equal(analyze('https://one-site.com/x', 'https://one-site.com/x#top', 'https://one-site.com/x').redirectCount, 1)
})

test('the hostnames of the hops are reported in order', () => {
  const r = analyze('https://one-site.com/a', 'https://two-site.net/b')
  assert.deepEqual(r.redirectChain, ['one-site.com', 'two-site.net'])
  assert.equal(r.redirectCount, 2)
})

test('missing input does not throw', () => {
  assert.deepEqual(analyzeRedirectChain(null), { hasRedirectChain: false, redirectCount: 0, redirectChain: [] })
})

test('very long chains are capped', () => {
  const urls = Array.from({ length: 30 }, (_, i) => `https://site${i}.com/`)
  assert.equal(analyzeRedirectChain(urls).redirectCount, 20)
})