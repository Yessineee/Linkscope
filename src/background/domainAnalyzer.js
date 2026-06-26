import { extractDomain, stripWWW } from '../utils/domainUtils.js'

const HOMOGLYPHS = {
  '0': 'o',
  '1': 'l',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '6': 'g',
  '8': 'b',
  'а': 'a',
  'е': 'e',
  'о': 'o',
  'р': 'p',
  'с': 'c',
  'х': 'x',
  'у': 'y',
}

function normalizeHomoglyphs(str) {
  let result = str.toLowerCase()
  result = result.replace(/vv/g, 'w')
  result = result.replace(/rn/g, 'm')
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
      const substitutionCost = a[i - 1] === b[j - 1] ? 0 : 1
      const fromDiagonal = grid[i - 1][j - 1] + substitutionCost
      const fromAbove    = grid[i - 1][j] + 1
      const fromLeft     = grid[i][j - 1] + 1
      grid[i][j] = Math.min(fromDiagonal, fromAbove, fromLeft)
    }
  }
  return grid[rows - 1][cols - 1]
}

const TOP_DOMAINS = [
  'google', 'facebook', 'youtube', 'amazon', 'twitter',
  'instagram', 'linkedin', 'microsoft', 'apple', 'netflix',
  'paypal', 'ebay', 'bank', 'chase', 'wellsfargo',
  'bankofamerica', 'citibank', 'hsbc', 'barclays', 'santander',
  'dropbox', 'github', 'gitlab', 'slack', 'discord',
  'whatsapp', 'telegram', 'reddit', 'pinterest', 'tumblr',
  'wordpress', 'shopify', 'stripe', 'coinbase', 'binance',
  'outlook', 'gmail', 'yahoo', 'icloud', 'protonmail',
]

export function analyzeDomain(url) {
  const domain = extractDomain(url)
  if (!domain) return { isLookalike: false, matchedBrand: null, distance: null, hasMixedScript: false }

  const cleanDomain = stripWWW(domain).toLowerCase()
  const domainWithoutTLD = cleanDomain.split('.')[0]

  // Detect Cyrillic characters or Punycode encoding (xn--)
  // Browsers convert unicode domains to Punycode before we see them
  const hasMixedScript =
    [...domainWithoutTLD].some(c => c.charCodeAt(0) >= 0x0400 && c.charCodeAt(0) <= 0x04FF) ||
    domainWithoutTLD.startsWith('xn--')

  const normalizedInput = normalizeHomoglyphs(domainWithoutTLD)

  // Only skip if the original domain matches a brand exactly
  if (TOP_DOMAINS.includes(domainWithoutTLD)) {
    return { isLookalike: false, matchedBrand: null, distance: 0, hasMixedScript: false }
  }

  let closestBrand = null
  let closestNormalizedDistance = Infinity
  let closestRawDistance = Infinity

  for (const brand of TOP_DOMAINS) {
    // Use normalized input for detection accuracy
    const normalizedDistance = levenshtein(normalizedInput, brand)
    if (normalizedDistance < closestNormalizedDistance) {
      closestNormalizedDistance = normalizedDistance
      // Use raw input for honest distance reporting
      closestRawDistance = levenshtein(domainWithoutTLD, brand)
      closestBrand = brand
    }
  }

  const isTyposquat = closestNormalizedDistance <= 2
  const isLookalike = isTyposquat || hasMixedScript

  return {
    isLookalike,
    matchedBrand: isTyposquat ? closestBrand : null,
    distance: closestRawDistance,
    hasMixedScript,
  }
}