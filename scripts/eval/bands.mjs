import { readFileSync, existsSync } from 'node:fs'
import { scoreUrl } from './score.mjs'
import { parseTranco, countBy, rateByBand, sample, seededRandom, RANK_BANDS } from './lib.mjs'

const file = new URL('../../data/top-1m.csv', import.meta.url)
if (!existsSync(file)) {
  console.error('Missing data/top-1m.csv')
  process.exit(1)
}

const rows = parseTranco(readFileSync(file, 'utf8'))
console.log(`Scoring ${rows.length} domains (local checks only)...`)

const scored = rows.map(({ rank, domain }) => ({ rank, domain, ...scoreUrl(`https://${domain}/`) }))
const flagged = scored.filter(item => item.score > 20)
console.log(`\nFlagged: ${flagged.length} of ${scored.length}`)

console.log('\nFlagged domains by popularity band:')
console.table(rateByBand(scored, 20, RANK_BANDS))

console.log('What would remain if every domain up to a given rank were exempt:')
console.table([1000, 10000, 50000, 100000].map(cutoff => {
  const below = scored.filter(item => item.rank > cutoff)
  const remaining = below.filter(item => item.score > 20).length
  return {
    exemptUpTo: cutoff,
    remaining,
    'per 1000 below the cutoff': ((remaining / below.length) * 1000).toFixed(2),
  }
}))

console.log('Brands behind the flagged domains (top 15):')
console.table(countBy(flagged, item => item.brand ?? 'none').slice(0, 15).map(([brand, count]) => ({ brand, count })))

console.log('Kinds of flag:')
console.table(countBy(flagged, item => item.kind).map(([kind, count]) => ({ kind, count })))

console.log('30 random flagged domains ranked below 100,000 (to judge which are real lookalikes):')
for (const item of sample(flagged.filter(row => row.rank > 100000), 30, seededRandom(1))) {
  console.log(`  rank ${item.rank}  ${item.domain}  ${item.kind}  ${item.brand}`)
}