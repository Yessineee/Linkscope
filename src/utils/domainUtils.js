const MULTI_PART_TLDS = new Set([
  'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk', 'net.uk',
  'co.jp', 'co.in', 'co.kr', 'co.nz', 'co.za', 'co.il',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'com.br', 'com.cn', 'com.mx', 'com.tr', 'com.sg',
  'co.id', 'co.th', 'co.ve',
])

export function extractDomain(url) {
  try {
    const hostname = new URL(url).hostname
    return extractDomainFromHostname(hostname)
  } catch {
    return null
  }
}


export function extractDomainFromHostname(hostname) {
  const parts = hostname.split('.')

  if (parts.length <= 2) return hostname

  const lastTwo = parts.slice(-2).join('.')
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.')
  }
  return parts.slice(-2).join('.')
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


export function extractSubdomain(hostname) {
  const domain = extractDomainFromHostname(hostname)
  if (hostname === domain) return ''
  return hostname.slice(0, hostname.length - domain.length - 1)
}