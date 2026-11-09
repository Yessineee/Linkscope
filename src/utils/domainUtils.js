import { registrableDomainOf } from '../core/url.js'

export function extractDomainFromHostname(hostname) {
  return registrableDomainOf(hostname)
}

export function isHTTPS(url) {
  try {
    return new URL(url).protocol === 'https:'
  } catch {
    return false
  }
}