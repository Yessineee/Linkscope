import test from 'node:test'
import assert from 'node:assert/strict'
import { seededRandom, shuffled, sample, parseFeedUrls, parseTranco, capPerKey, flaggedRate, countBy, defang } from '../scripts/eval/lib.mjs'

test('the same seed always gives the same numbers, all in [0, 1)', () => {
  const a = seededRandom(42)
  const b = seededRandom(42)
  for (let i = 0; i < 100; i++) {
    const x = a()
    assert.equal(x, b())
    assert.ok(x >= 0 && x < 1)
  }
})

test('different seeds give different sequences', () => {
  assert.notEqual(seededRandom(1)(), seededRandom(2)())
})

test('shuffling keeps the same items and does not touch the input', () => {
  const input = [1, 2, 3, 4, 5, 6, 7, 8]
  const copy = [...input]
  const out = shuffled(input, seededRandom(7))
  assert.deepEqual(input, copy)
  assert.deepEqual([...out].sort((x, y) => x - y), copy)
})

test('a sample has the requested size, no repeats, and is reproducible', () => {
  const input = Array.from({ length: 100 }, (_, i) => i)
  const a = sample(input, 10, seededRandom(5))
  const b = sample(input, 10, seededRandom(5))
  assert.equal(a.length, 10)
  assert.equal(new Set(a).size, 10)
  assert.deepEqual(a, b)
})

test('asking for more than exists returns everything', () => {
  assert.equal(sample([1, 2, 3], 10, seededRandom(1)).length, 3)
})

test('feed lines are trimmed, deduplicated, and non-web lines are dropped', () => {
  const text = 'http://a.example/x\r\n  https://b.example/y  \n\n# comment\nftp://c.example\nnot a url\nhttp://a.example/x\n'
  assert.deepEqual(parseFeedUrls(text), ['http://a.example/x', 'https://b.example/y'])
})

test('missing feed text gives an empty list', () => {
  assert.deepEqual(parseFeedUrls(null), [])
})

test('the Tranco list is parsed into rank and lowercase domain, skipping junk', () => {
  const text = '1,Google.com\r\n2,facebook.com\nrank,domain\n\n3,\nabc,example.com\n4,example.org\n'
  assert.deepEqual(parseTranco(text), [
    { rank: 1, domain: 'google.com' },
    { rank: 2, domain: 'facebook.com' },
    { rank: 4, domain: 'example.org' },
  ])
})

test('no more than the allowed number of items per key survive, in order', () => {
  const items = ['a1', 'a2', 'a3', 'b1', 'a4', 'b2']
  assert.deepEqual(capPerKey(items, item => item[0], 2), ['a1', 'a2', 'b1', 'b2'])
})

test('items without a key are dropped', () => {
  assert.deepEqual(capPerKey([1, 2, 3], n => (n === 2 ? null : 'k'), 5), [1, 3])
})

test('a score counts as flagged only when it is above the threshold', () => {
  const items = [{ score: 20 }, { score: 21 }, { score: 40 }, { score: 41 }]
  assert.deepEqual(flaggedRate(items, 20), { flagged: 3, total: 4, rate: 0.75 })
  assert.deepEqual(flaggedRate(items, 40), { flagged: 1, total: 4, rate: 0.25 })
})

test('an empty list has a flagged rate of 0, not NaN', () => {
  assert.deepEqual(flaggedRate([], 20), { flagged: 0, total: 0, rate: 0 })
})

test('counting handles single keys and lists of keys, most common first', () => {
  const items = [{ k: 'x' }, { k: ['x', 'y'] }, { k: 'y' }, { k: ['y'] }]
  assert.deepEqual(countBy(items, item => item.k), [['y', 3], ['x', 2]])
})

test('defanging breaks the scheme and every dot', () => {
  assert.equal(defang('http://evil.example.com/login.php'), 'hxxp://evil[.]example[.]com/login[.]php')
  assert.equal(defang('https://x.example/'), 'hxxps://x[.]example/')
})