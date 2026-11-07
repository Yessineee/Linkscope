import { parseUrl, registrableDomainOf } from '../core/url.js'

export function extractDomain(url) {
  const parsed = parseUrl(url)
  return parsed ? (parsed.registrableDomain ?? parsed.hostname) : null
}

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


export function extractSubdomain(hostname) {
  const domain = extractDomainFromHostname(hostname)
  if (hostname === domain) return ''
  return hostname.slice(0, hostname.length - domain.length - 1)
}