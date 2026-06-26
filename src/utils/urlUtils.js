import { extractDomain, extractHostname, stripWWW } from './domainUtils.js'


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
  if (!url) return true
  const skipped = [
    'chrome://',
    'chrome-extension://',
    'brave://',
    'about:',
    'data:',
    'file://',
    'javascript:',
  ]
  return skipped.some(prefix => url.startsWith(prefix))
}


export function isPrivateURL(url) {
  try {
    const hostname = extractHostname(url)
    if (!hostname) return false
    return (
      hostname === 'localhost' ||
      hostname.startsWith('127.') ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.16.') ||
      hostname.endsWith('.local')
    )
  } catch {
    return false
  }
}


export function getDisplayDomain(url) {
  try {
    const domain = extractDomain(url)
    return domain ? stripWWW(domain) : url
  } catch {
    return url
  }
}