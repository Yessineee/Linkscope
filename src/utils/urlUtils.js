import { parseUrl } from '../core/url.js'
import { cacheKeyFor } from '../core/cacheKey.js'

export function normalizeURL(url) {
  try {
    const parsed = new URL(url)
    parsed.hostname = parsed.hostname.toLowerCase()
    parsed.search = ''
    parsed.hash = ''
    return parsed.toString()
  } catch {
    return null
  }
}

export function getCacheKey(url) {
  return cacheKeyFor(url)
}

export function shouldSkipURL(url) {
  return parseUrl(url) === null
}

export function isPrivateURL(url) {
  return parseUrl(url)?.isPrivateNetwork ?? false
}