import { parseUrl } from './url.js'
import { cacheKeyFor } from './cacheKey.js'
import { isFirstPartyHost } from './legitimacy.js'

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const HEX = /^[0-9a-f]{16,}$/i
const JWT = /^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$/
const OWNER_AREA = /^\/u\/\d+(\/|$)/
const EDITOR = /\/edit$/

const skip = reason => ({ send: false, url: null, reason })

function decode(segment) {
  try {
    return decodeURIComponent(segment)
  } catch {
    return segment
  }
}

// Best effort, not a security boundary: recognises IDs and tokens that grant access to something.
function looksSecret(segment) {
  if (UUID.test(segment) || HEX.test(segment) || JWT.test(segment)) return true
  if (segment.length < 24 || !/^[A-Za-z0-9_-]+$/.test(segment)) return false

  // A long hyphenated run of real words is a readable title, not a token.
  const chunks = segment.split(/[-_]+/).filter(Boolean)
  const words = chunks.filter(chunk => /^[A-Za-z]+$/.test(chunk)).length
  if (chunks.length >= 3 && words / chunks.length >= 0.6) return false

  return /\d/.test(segment) || (/[a-z]/.test(segment) && /[A-Z]/.test(segment))
}

// Decides what, if anything, may be sent to external lookup services for a page.
// Returns { send, url, reason }; `url` is the reduced address to send.
export function lookupUrlFor(url) {
  const parsed = parseUrl(url)
  if (!parsed) return skip('invalid')

  const multiTenant = cacheKeyFor(url).includes('/')
  const path = parsed.pathname.replace(/\/+$/, '')

  if (multiTenant) {
    if (OWNER_AREA.test(path) || EDITOR.test(path)) return skip('owner-area')
  } else if (isFirstPartyHost(parsed)){
    return skip('brand-owned')
  }

  let sentPath = parsed.pathname
  if (!multiTenant) {
    // On multi-tenant hosts the path is the page's identity, so it is kept.
    const segments = parsed.pathname.split('/').filter(Boolean)
    const cut = segments.findIndex(segment => looksSecret(decode(segment)))
    if (cut !== -1) sentPath = '/' + segments.slice(0, cut).join('/')
  }

  const full = new URL(url)
  const port = full.port ? `:${full.port}` : ''
  return { send: true, url: `${full.protocol}//${parsed.hostname}${port}${sentPath}`, reason: null }
}