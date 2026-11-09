import test from 'node:test'
import assert from 'node:assert/strict'
import { cacheKeyFor } from '../src/core/cacheKey.js'

test('ordinary sites are keyed by hostname, ignoring www, path, query and hash', () => {
  assert.equal(cacheKeyFor('https://www.Example.com/a/b?c=1#d'), 'example.com')
})

test('two pages on an ordinary site share one key', () => {
  assert.equal(cacheKeyFor('https://example.com/one'), cacheKeyFor('https://example.com/two'))
})

test('Google Forms are keyed by page, and the query string is ignored', () => {
  const a = cacheKeyFor('https://docs.google.com/forms/d/e/AAA/viewform?usp=sf_link')
  const b = cacheKeyFor('https://docs.google.com/forms/d/e/BBB/viewform')
  assert.equal(a, 'docs.google.com/forms/d/e/AAA/viewform')
  assert.notEqual(a, b)
})

test('other Google Docs services stay keyed by host', () => {
  assert.equal(cacheKeyFor('https://docs.google.com/document/d/ABC/edit'), 'docs.google.com')
  assert.equal(cacheKeyFor('https://docs.google.com/spreadsheets/d/ABC/edit'), 'docs.google.com')
})

test('whole-host rules key every page separately, and the root is the host', () => {
  assert.notEqual(cacheKeyFor('https://sites.google.com/view/one'), cacheKeyFor('https://sites.google.com/view/two'))
  assert.equal(cacheKeyFor('https://sites.google.com/'), 'sites.google.com')
})

test('a path prefix only matches whole path segments', () => {
  assert.equal(cacheKeyFor('https://docs.google.com/formsfoo/x'), 'docs.google.com')
  assert.equal(cacheKeyFor('https://docs.google.com/forms'), 'docs.google.com/forms')
})

test('a trailing slash does not create a second key', () => {
  assert.equal(cacheKeyFor('https://sites.google.com/view/one/'), cacheKeyFor('https://sites.google.com/view/one'))
})

test('the path is case-sensitive, the host is not', () => {
  assert.notEqual(cacheKeyFor('https://sites.google.com/view/Abc'), cacheKeyFor('https://sites.google.com/view/abc'))
  assert.equal(cacheKeyFor('https://SITES.google.com/view/x'), 'sites.google.com/view/x')
})

test('invalid and non-web URLs have no key', () => {
  assert.equal(cacheKeyFor('chrome://extensions'), null)
  assert.equal(cacheKeyFor('ftp://example.com/file'), null)
  assert.equal(cacheKeyFor('not a url'), null)
})

test('very long paths are capped', () => {
  const key = cacheKeyFor('https://sites.google.com/view/' + 'a'.repeat(500))
  assert.ok(key.startsWith('sites.google.com/view/aaa'))
  assert.ok(key.length <= 'sites.google.com'.length + 200)
})

test('a trailing-dot hostname gets the same key as the plain one', () => {
  assert.equal(cacheKeyFor('https://sites.google.com./view/x'), 'sites.google.com/view/x')
})

test('lookalike hosts do not match a multi-tenant rule', () => {
  assert.equal(cacheKeyFor('https://sites.google.com.evil.com/view/x'), 'sites.google.com.evil.com')
  assert.equal(cacheKeyFor('https://notsites.google.com/view/x'), 'notsites.google.com')
})