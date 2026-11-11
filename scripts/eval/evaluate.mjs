import { readFileSync, existsSync, writeFileSync } from 'node:fs'
import { analyzeDomain } from '../../src/background/domainAnalyzer.js'
import { calculateRiskScore } from '../../src/background/riskScorer.js'
import { parseUrl } from '../../src/core/url.js'
import { isBrandOwnedHost } from '../../src/core/legitimacy.js'
import { isHTTPS } from '../../src/utils/domainUtils.js'
import { seededRandom, shuffled, sample, parseFeedUrls, parseTranco, capPerKey, flaggedRate, countBy, defang } from './lib.mjs'

function option(name, fallback) {
  const i = process.argv.indexOf(`--${name}`)
  return i === -1 ? fallback : Number(process.argv[i + 1])
}

const SEED = option('seed', 42)
const POSITIVES = option('positives', 5000)
const TAIL_SIZE = option('tail', 5000)
const MAX_PER_DOMAIN = option('max-per-domain', 3)
const HEAD_RANK = 1000
const TAIL_FROM_RANK = 10000

const dataFile = name => new URL(`../../data/${name}`, import.meta.url)
const readData = name => (existsSync(dataFile(name)) ? readFileSync(dataFile(name), 'utf8') : null)

function scoreUrl(url) {
  const domain = analyzeDomain(url)
  const result = calculateRiskScore(domain, null, null, null, { isHTTPS: isHTTPS(url) })
  return {
    score: result.score,
    level: result.riskLevel.label,
    signals: result.signals.map(signal => signal.id),
    kind: domain.kind ?? 'none',
  }
}

function hostKind(url) {
  const parsed = parseUrl(url)
  if (!parsed) return 'invalid'
  if (parsed.isIp) return 'ip-address'
  if (isBrandOwnedHost(parsed)) return 'brand-owned'
  if (parsed.onSharedHost) return 'shared-hosting'
  return 'ordinary-domain'
}

const percent = rate => `${(rate * 100).toFixed(1)}%`

// ---- load the data ----
const random = seededRandom(SEED)

const phishingSources = [
  { name: 'openphish', file: 'openphish.txt' },
  { name: 'phishing-database', file: 'phishing-database.txt' },
]
const pool = []
const seenUrls = new Set()
for (const { name, file } of phishingSources) {
  const text = readData(file)
  if (text === null) {
    console.log(`(missing data/${file}, skipping)`)
    continue
  }
  const urls = parseFeedUrls(text)
  console.log(`${name}: ${urls.length} web addresses`)
  for (const url of urls) {
    if (!seenUrls.has(url)) {
      seenUrls.add(url)
      pool.push({ url, source: name })
    }
  }
}

const trancoText = readData('top-1m.csv')
if (pool.length === 0 || trancoText === null) {
  console.error('Missing data. Expected data/top-1m.csv and at least one phishing list in data/.')
  process.exit(1)
}

// ---- build the two sets ----
const positives = capPerKey(
  shuffled(pool, random),
  item => {
    const parsed = parseUrl(item.url)
    return parsed ? (parsed.registrableDomain ?? parsed.hostname) : null
  },
  MAX_PER_DOMAIN
)
  .slice(0, POSITIVES)
  .map(item => ({ ...item, ...scoreUrl(item.url) }))

const ranked = parseTranco(trancoText)
const toNegative = ({ rank, domain }) => ({ rank, domain, ...scoreUrl(`https://${domain}/`) })
const head = ranked.filter(row => row.rank <= HEAD_RANK).map(toNegative)
const tail = sample(ranked.filter(row => row.rank > TAIL_FROM_RANK), TAIL_SIZE, random).map(toNegative)

console.log(`\nSeed ${SEED}. Phishing sample: ${positives.length} (max ${MAX_PER_DOMAIN} per domain). Popular sites: ${head.length} (top ${HEAD_RANK}). Long-tail sites: ${tail.length} (rank above ${TAIL_FROM_RANK}).`)

// ---- results at each warning level ----
const levels = [
  { name: 'any warning (LOW or higher)', above: 20 },
  { name: 'overlay (SUSPICIOUS or higher)', above: 40 },
  { name: 'DANGEROUS', above: 70 },
]

const summary = levels.map(({ name, above }) => {
  const caught = flaggedRate(positives, above)
  const headAlarms = flaggedRate(head, above)
  const tailAlarms = flaggedRate(tail, above)
  return {
    level: name,
    'phishing caught': percent(caught.rate),
    'false alarms per 1000 (top sites)': (headAlarms.rate * 1000).toFixed(1),
    'false alarms per 1000 (long tail)': (tailAlarms.rate * 1000).toFixed(1),
  }
})
console.log('\nLocal checks only (no APIs, no page content):')
console.table(summary)

console.log('Phishing caught by source, at any warning:')
console.table(phishingSources.map(({ name }) => {
  const own = positives.filter(item => item.source === name)
  const { flagged, total, rate } = flaggedRate(own, 20)
  return { source: name, sampled: total, caught: flagged, rate: percent(rate) }
}))

console.log('Signals that fired on phishing addresses:')
console.table(countBy(positives, item => (item.signals.length ? item.signals : 'none')).map(([signal, count]) => ({ signal, count })))

const missed = positives.filter(item => item.score <= 20)
console.log(`Missed phishing (${missed.length}) by kind of host:`)
console.table(countBy(missed, item => hostKind(item.url)).map(([host, count]) => ({ host, count })))

const falseAlarms = [...head, ...tail].filter(item => item.score > 20)
console.log(`\nFalse alarms among legitimate sites: ${falseAlarms.length}`)
console.table(countBy(falseAlarms, item => item.kind).map(([kind, count]) => ({ kind, count })))
console.log('Examples:')
for (const item of falseAlarms.slice(0, 30)) {
  console.log(`  rank ${item.rank}  ${item.domain}  score ${item.score}  ${item.kind}`)
}

// ---- files (the addresses in them are defanged) ----
writeFileSync(dataFile('eval-misses.txt'), missed.slice(0, 300).map(item => defang(item.url)).join('\n') + '\n')
writeFileSync(dataFile('eval-report.json'), JSON.stringify({
  generatedAt: new Date().toISOString(),
  seed: SEED,
  sizes: { phishing: positives.length, head: head.length, tail: tail.length },
  summary,
  falseAlarms: falseAlarms.map(({ rank, domain, score, kind }) => ({ rank, domain, score, kind })),
}, null, 2))
console.log('\nWrote data/eval-misses.txt (defanged samples) and data/eval-report.json')