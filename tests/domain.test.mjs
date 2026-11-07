import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeDomain } from '../src/background/domainAnalyzer.js'
import { extractDomain } from '../src/utils/domainUtils.js'
import { isPrivateURL } from '../src/utils/urlUtils.js'

// --- the six bugs ---

test('trailing dot does not hide a lookalike', () => {
  assert.equal(analyzeDomain('https://paypa1.com./login').isLookalike, true)
})

test('a subdomain named "10" is not a private IP', () => {
  assert.equal(isPrivateURL('http://10.paypal-login.com/'), false)
})

test('brand impersonation on a shared host is flagged', () => {
  // YOUR CALL: should this be flagged? I'd say yes, since "paypal" is not
  // paypal.com. Change the expectation if you decide otherwise.
  assert.equal(analyzeDomain('https://paypal.github.io/').isLookalike, true)
})

test('brand in a subdomain of an unrelated domain is flagged', () => {
  const r = analyzeDomain('https://paypal.evil.com/')
  assert.equal(r.isLookalike, true)
  assert.equal(r.matchedBrand, 'paypal')
})

test('multi-part public suffix is handled', () => {
  assert.equal(extractDomain('https://bank.com.ng/'), 'bank.com.ng')
})

test('a legitimate IDN is not treated as a homograph attack', () => {
  const r = analyzeDomain('https://müller.de/')
  assert.equal(r.hasMixedScript, false)
  assert.equal(r.isLookalike, false)
})

// --- guards: fixes must not break these ---

test('the real brand domain stays safe', () => {
  assert.equal(analyzeDomain('https://www.paypal.com/signin').isLookalike, false)
})

test('real private addresses are still skipped', () => {
  assert.equal(isPrivateURL('http://192.168.1.10/'), true)
})


test('brand glued to a credential word is flagged', () => {
  assert.equal(analyzeDomain('https://paypalverify.com/').isLookalike, true)
})

test('brand used as an ordinary word is not flagged', () => {
  assert.equal(analyzeDomain('https://apple-pie-recipes.com/').isLookalike, false)
})

test('country variants of a real brand stay safe', () => {
  assert.equal(analyzeDomain('https://www.google.fr/').isLookalike, false)
  assert.equal(analyzeDomain('https://www.amazon.co.uk/').isLookalike, false)
  assert.equal(analyzeDomain('https://www.bbc.co.uk/').isLookalike, false)
})

test('same brand name on an unrelated suffix is flagged', () => {
  assert.equal(analyzeDomain('https://google.xyz/').isLookalike, true)
})

test('subdomains of a real brand stay safe', () => {
  assert.equal(analyzeDomain('https://accounts.google.com/').isLookalike, false)
})

test('brand hidden in a subdomain chain is flagged', () => {
  assert.equal(analyzeDomain('https://login.paypal.com.evil.com/').isLookalike, true)
})

test('a bare public suffix does not crash', () => {
  assert.equal(analyzeDomain('https://github.io/').isLookalike, false)
})

test('Cyrillic letter inside a Latin brand is flagged', () => {
  const r = analyzeDomain('https://аpple.com/') // first letter is Cyrillic
  assert.equal(r.hasMixedScript, true)
  assert.equal(r.isLookalike, true)
  assert.equal(r.matchedBrand, 'apple')
})

test('a fully Cyrillic legitimate domain is not mixed-script', () => {
  assert.equal(analyzeDomain('https://яндекс.рф/').hasMixedScript, false)
})