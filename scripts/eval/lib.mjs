// Pure helpers for the evaluation scripts: no network, no files, no extension code.

// A small seeded random generator (mulberry32), so every run of the evaluation can be reproduced.
export function seededRandom(seed) {
  let a = seed | 0
  return () => {
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function shuffled(items, random) {
  const out = [...items]
  for (let i = out.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1))
    ;[out[i], out[j]] = [out[j], out[i]]
  }
  return out
}

export function sample(items, count, random) {
  return shuffled(items, random).slice(0, count)
}

// One address per line; keeps only http(s) lines and removes duplicates.
export function parseFeedUrls(text) {
  const seen = new Set()
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const url = line.trim()
    if (/^https?:\/\//i.test(url)) seen.add(url)
  }
  return [...seen]
}

// "rank,domain" lines, as in the Tranco list.
export function parseTranco(text) {
  const rows = []
  for (const line of String(text ?? '').split(/\r?\n/)) {
    const comma = line.indexOf(',')
    if (comma === -1) continue
    const rank = Number(line.slice(0, comma))
    const domain = line.slice(comma + 1).trim().toLowerCase()
    if (!Number.isInteger(rank) || rank < 1 || !domain) continue
    rows.push({ rank, domain })
  }
  return rows
}

// Keeps at most `max` items per key, so one hacked site or campaign can't dominate the sample.
export function capPerKey(items, keyFn, max) {
  const counts = new Map()
  const out = []
  for (const item of items) {
    const key = keyFn(item)
    if (key == null) continue
    const seen = counts.get(key) ?? 0
    if (seen >= max) continue
    counts.set(key, seen + 1)
    out.push(item)
  }
  return out
}

export function flaggedRate(items, threshold) {
  const flagged = items.filter(item => item.score > threshold).length
  return { flagged, total: items.length, rate: items.length === 0 ? 0 : flagged / items.length }
}

// Counts keys across items (a key function may return one key or a list), most common first.
export function countBy(items, keyFn) {
  const counts = new Map()
  for (const item of items) {
    for (const key of [].concat(keyFn(item))) counts.set(key, (counts.get(key) ?? 0) + 1)
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1])
}

// Makes an address safe to display: it can't be opened by a click or a paste into a browser.
export function defang(url) {
  return String(url).replace(/^http/i, 'hxxp').replace(/\./g, '[.]')
}

export const RANK_BANDS = [[1, 1000], [1001, 10000], [10001, 50000], [50001, 100000], [100001, 1000000]]

// Flag rate per popularity band: how many domains in each rank range were flagged.
export function rateByBand(items, threshold, bands = RANK_BANDS) {
  return bands.map(([from, to]) => {
    const inBand = items.filter(item => item.rank >= from && item.rank <= to)
    const flagged = inBand.filter(item => item.score > threshold).length
    return {
      band: `${from}-${to}`,
      total: inBand.length,
      flagged,
      perThousand: inBand.length === 0 ? 0 : Number(((flagged / inBand.length) * 1000).toFixed(2)),
    }
  })
}