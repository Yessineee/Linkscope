

export function extractDomain(url) {
  try {
    const hostname = new URL(url).hostname
    const parts = hostname.split('.')
    if (parts.length <= 2) return hostname
    return parts.slice(-2).join('.')
  } catch {
    return null
  }
}


export function extractHostname(url) {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
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


export function extractTLD(hostname) {
  const parts = hostname.split('.')
  return parts[parts.length - 1]
}


export function extractSubdomain(hostname) {
  const parts = hostname.split('.')
  if (parts.length <= 2) return ''
  return parts.slice(0, -2).join('.')
}