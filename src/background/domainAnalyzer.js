import { parseUrl } from '../core/url.js'
import {
  BRANDS, ALLOWED_DOMAINS, TYPO_EXCLUDED, WORD_BRANDS,
  COUNTRY_VARIANT_BRANDS, COMMON_COUNTRY_CODES, SUSPICIOUS_WORDS,
  TOP_GLOBAL_DOMAINS, KNOWN_REDIRECT_SERVICES,
} from '../core/brands.js'

export { TOP_GLOBAL_DOMAINS, KNOWN_REDIRECT_SERVICES }


const CONFUSABLE_SCRIPTS = [
  /\p{Script=Latin}/u,
  /\p{Script=Cyrillic}/u,
  /\p{Script=Greek}/u,
  /\p{Script=Armenian}/u,
]

function hasMixedConfusableScripts(label) {
  return CONFUSABLE_SCRIPTS.filter(re => re.test(label)).length > 1
}

const HOMOGLYPHS = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '8': 'b',
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y',
}

function normalizeHomoglyphs(str) {
  let result = str.toLowerCase()
  result = result.replace(/vv/g, 'w').replace(/rn/g, 'm')
  return result.split('').map(char => HOMOGLYPHS[char] ?? char).join('')
}

function levenshtein(a, b) {
  const rows = a.length + 1
  const cols = b.length + 1
  const grid = Array.from({ length: rows }, () => Array(cols).fill(0))
  for (let i = 0; i < rows; i++) grid[i][0] = i
  for (let j = 0; j < cols; j++) grid[0][j] = j
  for (let i = 1; i < rows; i++) {
    for (let j = 1; j < cols; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1
      grid[i][j] = Math.min(grid[i - 1][j - 1] + cost, grid[i - 1][j] + 1, grid[i][j - 1] + 1)
    }
  }
  return grid[rows - 1][cols - 1]
}

const BRAND_LABELS = Object.keys(BRANDS)
const IMPERSONATION_BRANDS = BRAND_LABELS.filter(b => b.length >= 3 && !WORD_BRANDS.has(b))
const TYPO_BRANDS = BRAND_LABELS.filter(b => b.length >= 5 && !TYPO_EXCLUDED.has(b) && !WORD_BRANDS.has(b))
const LONG_SUSPICIOUS = [...SUSPICIOUS_WORDS].filter(w => w.length >= 5)

function maxTypoDistance(brand) {
  return brand.length >= 8 ? 2 : 1
}

function isLegitimate(p) {
  if (ALLOWED_DOMAINS.has(p.registrableDomain)) return true
  if (COUNTRY_VARIANT_BRANDS.has(p.domainLabel) && !p.onSharedHost) {
    const countryCode = p.publicSuffix.split('.').pop()
    return COMMON_COUNTRY_CODES.has(countryCode)
  }
  return false
}

function findBrandMisuse(p, label) {
  // 1. A brand's exact name on a domain that isn't theirs (paypal.xyz, paypal.github.io)
  if (IMPERSONATION_BRANDS.includes(label)) {
    return { kind: 'wrong-domain', brand: label, distance: 0 }
  }

  // 2. A brand name used as a subdomain of someone else's domain (paypal.evil.com)
  const subdomainTokens = p.subdomainLabels.flatMap(l => l.split(/[-_]+/))
  const inSubdomain = IMPERSONATION_BRANDS.find(b => subdomainTokens.includes(b))
  if (inSubdomain) {
    return { kind: 'brand-in-subdomain', brand: inSubdomain, distance: 0 }
  }

  // 3. Typosquats (paypa1.com) and hyphenated combosquats (paypal-verify.com)
  const tokens = label.split(/[-_]+/).filter(t => t.length >= 3)
  const isMultiToken = tokens.length > 1
  const candidates = isMultiToken ? tokens : [label]

  let best = null
  for (const candidate of candidates) {
    const normalized = normalizeHomoglyphs(candidate)
    for (const brand of TYPO_BRANDS) {
      if (Math.abs(normalized.length - brand.length) > 2) continue
      const distance = levenshtein(normalized, brand)
      if (distance <= maxTypoDistance(brand) && (best === null || distance < best.distance)) {
        best = { brand, distance }
      }
    }
  }

  if (best && isMultiToken) {
    const hasSuspiciousWord = tokens.some(t => SUSPICIOUS_WORDS.has(normalizeHomoglyphs(t)))
    if (!hasSuspiciousWord) best = null
  }
  if (best) {
    return { kind: isMultiToken ? 'combosquat' : 'typosquat', brand: best.brand, distance: best.distance }
  }

  // 4. Brand glued to a credential word with no separator (paypalverify.com)
  const glued = IMPERSONATION_BRANDS.find(b =>
    b.length >= 5 && label.includes(b) && LONG_SUSPICIOUS.some(w => label.includes(w))
  )
  if (glued) {
    return { kind: 'combosquat', brand: glued, distance: 0 }
  }

  return null
}

export function analyzeDomain(url) {
  const neutral = { isLookalike: false, matchedBrand: null, distance: null, hasMixedScript: false, kind: null }

  const p = parseUrl(url)
  if (!p || !p.registrableDomain || !p.domainLabel) return neutral

  const label = p.domainLabelUnicode.toLowerCase()
  const hasMixedScript = hasMixedConfusableScripts(label)

  if (isLegitimate(p)) return { ...neutral, distance: 0 }

  const hit = findBrandMisuse(p, label)

  return {
    isLookalike: hit !== null || hasMixedScript,
    matchedBrand: hit?.brand ?? null,
    distance: hit?.distance ?? null,
    hasMixedScript,
    kind: hit?.kind ?? (hasMixedScript ? 'mixed-script' : null),
  }
}