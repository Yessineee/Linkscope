import { parseUrl } from './url.js'
import { isFirstPartyHost } from './legitimacy.js'
import { KNOWN_REDIRECT_SERVICES } from './brands.js'

const MAX_HOPS = 20

function withoutHash(url) {
  const u = new URL(url)
  u.hash = ''
  return u.href
}

// Turns the list of addresses a page load went through into a verdict about the redirect chain.
export function analyzeRedirectChain(chain) {
  const hops = []
  for (const raw of (chain ?? []).slice(0, MAX_HOPS)) {
    const parsed = parseUrl(raw)
    if (!parsed) continue
    const href = withoutHash(raw)
    if (hops.length > 0 && hops[hops.length - 1].href === href) continue
    hops.push({ href, parsed })
  }

  const siteOf = parsed => parsed.registrableDomain ?? parsed.hostname
  const untrusted = hops.filter(({ parsed }) =>
    !isFirstPartyHost(parsed) && !KNOWN_REDIRECT_SERVICES.has(siteOf(parsed))
  )
  const sites = new Set(untrusted.map(({ parsed }) => siteOf(parsed)))

  return {
    hasRedirectChain: untrusted.length > 2 && sites.size > 1,
    redirectCount: hops.length,
    redirectChain: hops.map(({ parsed }) => parsed.hostname),
  }
}