export function detectSuspiciousRedirects(serviceWorkerRedirectResult = null) {
  if (serviceWorkerRedirectResult) {
    return serviceWorkerRedirectResult
  }

  const entries = performance.getEntriesByType('navigation')
  const redirectCount = entries.length > 0 ? (entries[0].redirectCount ?? 0) : 0

  const chain = [window.location.hostname]
  if (document.referrer) {
    try {
      const referrerDomain = new URL(document.referrer).hostname
      if (referrerDomain !== window.location.hostname) {
        chain.unshift(referrerDomain)
      }
    } catch {
        // Ignore invalid referrer URL
    }
  }

  const getBase = domain => domain.split('.').slice(-2).join('.')
  const uniqueDomains = new Set(chain.map(getBase))
  const crossDomain = uniqueDomains.size >= 2

  return {
    hasRedirectChain: redirectCount > 2 || crossDomain,
    redirectCount,
    redirectChain: chain,
    crossDomain,
  }
}