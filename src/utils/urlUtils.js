import { extractHostname, stripWWW } from './domainUtils.js'
import { parseUrl } from '../core/url.js'

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
  try {
    const hostname = extractHostname(url)
    if (!hostname) return null
    return stripWWW(hostname.toLowerCase())
  } catch {
    return null
  }
}

export function shouldSkipURL(url) {
  return parseUrl(url) === null
}

export function isPrivateURL(url) {
  return parseUrl(url)?.isPrivateNetwork ?? false
}
