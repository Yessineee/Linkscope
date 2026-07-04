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

// Master list of well-known legitimate domains. Used for:
//   1. Exact-match exemption (visiting the real site is never flagged)
//   2. Redirect-chain trust (worker.js)
//   3. The base set for typosquat comparison, minus TYPOSQUAT_COMPARISON_EXCLUSIONS below
export const TOP_GLOBAL_DOMAINS = new Set([
  'google', 'youtube', 'facebook', 'instagram', 'twitter', 'x', 'whatsapp',
  'wikipedia', 'amazon', 'yahoo', 'reddit', 'tiktok', 'linkedin', 'netflix',
  'bing', 'pinterest', 'twitch', 'microsoft', 'apple', 'spotify', 'discord',
  'ebay', 'office', 'live', 'cloudflare', 'github', 'gitlab', 'stackoverflow',
  'zoom', 'dropbox', 'salesforce', 'adobe', 'paypal', 'shopify', 'wordpress',
  'quora', 'imdb', 'walmart', 'target', 'bestbuy', 'etsy', 'craigslist',
  'booking', 'airbnb', 'uber', 'lyft', 'doordash', 'tripadvisor', 'expedia',
  'cnn', 'bbc', 'nytimes', 'forbes', 'medium', 'wsj', 'theguardian',
  'espn', 'nba', 'nfl', 'fifa', 'chase', 'wellsfargo', 'bankofamerica',
  'citibank', 'hsbc', 'barclays', 'americanexpress', 'visa', 'mastercard',
  'coinbase', 'binance', 'kraken', 'robinhood', 'fidelity', 'schwab',
  'samsung', 'sony', 'lg', 'dell', 'hp', 'lenovo', 'intel', 'nvidia',
  'tesla', 'spacex', 'openai', 'anthropic', 'slack', 'notion', 'figma',
  'canva', 'atlassian', 'jira', 'trello', 'asana', 'monday', 'hubspot',
  'mailchimp', 'stripe', 'square', 'venmo', 'zelle', 'indeed', 'glassdoor',
  'monster', 'ziprecruiter', 'coursera', 'udemy', 'khanacademy', 'duolingo',
  'gmail', 'icloud', 'protonmail', 'outlook', 'wetransfer',
  'telegram', 'signal', 'snapchat', 'flickr', 'vimeo',
])

export const KNOWN_REDIRECT_SERVICES = new Set([
  't.co', 'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
  'buff.ly', 'is.gd', 'rebrand.ly', 'lnkd.in', 'youtu.be',
])

// Brands excluded from *typosquat comparison* specifically (they still get
// the exact-match exemption above via TOP_GLOBAL_DOMAINS). Excluded because
// comparing against them causes false positives on unrelated legitimate
// domains, for one of two reasons:
//   - Too short (<=4 chars): at Levenshtein distance <=2, a 4-character-or-
//     shorter string matches an enormous number of unrelated domains by pure
//     chance (e.g. almost any 3-letter domain is within distance 2 of 'x').
//   - Common, generic English word: even at a safer length, words that show
//     up constantly in unrelated legitimate domain names (e.g. 'target',
//     'office') generate frequent coincidental false positives.
// This is deliberately the ONLY place brand-comparison exclusions live -
// TOP_DOMAINS below is derived from TOP_GLOBAL_DOMAINS, not hand-duplicated,
// so this list can't silently drift out of sync with it again.
const TYPOSQUAT_COMPARISON_EXCLUSIONS = new Set([
  'x', 'lg', 'hp', 'bbc', 'cnn', 'wsj', 'nba', 'nfl', 'fifa', 'bing',
  'dell', 'espn', 'etsy', 'imdb', 'jira', 'live', 'lyft', 'sony', 'uber',
  'visa', 'zoom',
  'office', 'target', 'square', 'medium', 'monday', 'indeed', 'intel',
  'monster', 'booking',
])

const TOP_DOMAINS = [...TOP_GLOBAL_DOMAINS].filter(
  brand => !TYPOSQUAT_COMPARISON_EXCLUSIONS.has(brand)
)

// Words commonly paired with a brand name in real combosquat phishing domains
// (e.g. 'paypal-verify.com', 'chase-secure-login.com'). Requiring one of
// these alongside a brand-token match is what separates real attack patterns
// from an unrelated hyphenated domain that happens to contain a brand name
// as an ordinary word (e.g. 'apple-pie-recipes.com', 'tesla-fan-club.com').
const SUSPICIOUS_COMBOSQUAT_WORDS = new Set([
  'login', 'signin', 'verify', 'verification',
  'secure', 'security', 'account', 'update', 'confirm', 'confirmation',
  'password', 'billing', 'payment', 'support', 'service', 'recover',
  'recovery', 'unlock', 'suspended', 'authenticate', 'auth', 'validate',
  'validation', 'alert', 'restore', 'reactivate',
])

export function analyzeDomain(url) {
  const domain = extractDomain(url)
  if (!domain) return { isLookalike: false, matchedBrand: null, distance: null, hasMixedScript: false }

  const cleanDomain = stripWWW(domain).toLowerCase()
  const domainWithoutTLD = cleanDomain.split('.')[0]

  // Detect Cyrillic characters or Punycode encoding (xn--)
  // Browsers convert unicode domains to Punycode before we see them
  const hasMixedScript =
    [...domainWithoutTLD].some(c => c.charCodeAt(0) >= 0x0400 && c.charCodeAt(0) <= 0x04FF) || domainWithoutTLD.startsWith('xn--')

  // Exact match to any known-legitimate domain always short-circuits as safe,
  // including brands excluded from typosquat comparison above (e.g. 'target',
  // 'office') - they're just never used as *comparison targets* for detecting
  // near-miss typosquats of other domains.
  if (TOP_GLOBAL_DOMAINS.has(domainWithoutTLD)) {
    return { isLookalike: false, matchedBrand: null, distance: 0, hasMixedScript: false }
  }

  const tokens = domainWithoutTLD.split(/[-_]+/).filter(t => t.length >= 3)
  const isMultiToken = tokens.length > 1
  const candidates = isMultiToken ? tokens : [domainWithoutTLD]

  let closestBrand = null
  let closestNormalizedDistance = Infinity
  let closestRawDistance = Infinity

  for (const candidate of candidates) {
    const normalizedCandidate = normalizeHomoglyphs(candidate)
    for (const brand of TOP_DOMAINS) {
      // Use normalized input for detection accuracy
      const normalizedDistance = levenshtein(normalizedCandidate, brand)
      if (normalizedDistance < closestNormalizedDistance) {
        closestNormalizedDistance = normalizedDistance
        // Use raw input for honest distance reporting
        closestRawDistance = levenshtein(candidate, brand)
        closestBrand = brand
      }
    }
  }

  let isTyposquat = closestNormalizedDistance <= 2

  // Combosquat patterns (e.g. 'paypal-verify.com') hide a real brand name
  // behind extra hyphenated words. For multi-token domains, only confirm the
  // match if a credential/account-related word is also present - otherwise
  // a brand name appearing as an ordinary word in an unrelated domain (e.g.
  // 'apple-pie-recipes.com', 'tesla-fan-club.com') would be false-flagged.
  if (isTyposquat && isMultiToken) {
    const hasSuspiciousWord = tokens.some(t => SUSPICIOUS_COMBOSQUAT_WORDS.has(normalizeHomoglyphs(t)))
    if (!hasSuspiciousWord) {
      isTyposquat = false
    }
  }

  const isLookalike = isTyposquat || hasMixedScript

  return {
    isLookalike,
    matchedBrand: isTyposquat ? closestBrand : null,
    distance: closestRawDistance,
    hasMixedScript,
  }
}