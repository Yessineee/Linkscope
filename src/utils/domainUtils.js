import { parseUrl, registrableDomainOf } from '../core/url.js'

export function extractDomainFromHostname(hostname) {
  return registrableDomainOf(hostname)
}

export function extractHostname(url) {
  return parseUrl(url)?.hostname ?? null
}

export function stripWWW(hostname) {
  return hostname.startsWith('www.') ? hostname.slice(4) : hostname
}

export function isHTTPS(url) {
  try {
    return new URL(url).protocol === 'https:'
  } catch {
    return false
  }
}