import { parse } from 'tldts'
import punycode from 'punycode/punycode.js'



function decodeLabel(label) {
  try {
    return punycode.toUnicode(label)
  } catch {
    return label
  }
}

function isPrivateIPv4(host) {
  const p = host.split('.').map(Number)
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return false
  const [a, b] = p
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  )
}

function isPrivateIPv6(host) {
  const h = host.replace(/^\[|\]$/g, '')
  return h === '::1' || h === '::' || /^f[cd]/.test(h) || /^fe[89ab]/.test(h)
}

function isPrivateNetworkHost(hostname, isIp) {
  if (isIp) return isPrivateIPv4(hostname) || isPrivateIPv6(hostname)
  return (
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local')
  )
}

export function parseUrl(raw) {
  let url
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null

  const hostname = url.hostname.replace(/\.$/, '')
  const parts = parse(hostname, { allowPrivateDomains: true })

  return {
    hostname,
    pathname: url.pathname,
    registrableDomain: parts.domain,
    domainLabel: parts.domainWithoutSuffix,
    publicSuffix: parts.publicSuffix,
    subdomainLabels: parts.subdomain ? parts.subdomain.split('.').map(decodeLabel) : [],
    domainLabelUnicode: decodeLabel(parts.domainWithoutSuffix ?? ''),
    isIp: parts.isIp,
    onSharedHost: parts.isPrivate === true,
    isPrivateNetwork: isPrivateNetworkHost(hostname, parts.isIp === true),
  }
}


export function registrableDomainOf(hostname) {
  const clean = String(hostname ?? '').toLowerCase().replace(/\.$/, '')
  return parse(clean, { allowPrivateDomains: true }).domain ?? clean
}