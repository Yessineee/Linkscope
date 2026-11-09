import { parseUrl } from './url.js'
import { MULTI_TENANT_PATHS } from './brands.js'

const MAX_PATH_KEY_LENGTH = 200

// "docs.google.com/forms" -> { host: 'docs.google.com', prefix: '/forms' }; "sites.google.com" -> prefix ''.
const RULES = MULTI_TENANT_PATHS.map(rule => {
  const slash = rule.indexOf('/')
  return slash === -1 ? { host: rule, prefix: '' } : { host: rule.slice(0, slash), prefix: rule.slice(slash) }
})

function matchesRule(host, path) {
  return RULES.some(rule =>
    rule.host === host &&
    (rule.prefix === '' || path === rule.prefix || path.startsWith(`${rule.prefix}/`))
  )
}

// The key under which a page's cached results and whitelist entry are stored.
// Normally the hostname; on multi-tenant hosts, the hostname plus the path.
export function cacheKeyFor(url) {
  const parsed = parseUrl(url)
  if (!parsed) return null

  const host = parsed.hostname.startsWith('www.') ? parsed.hostname.slice(4) : parsed.hostname
  const path = parsed.pathname.replace(/\/+$/, '')

  if (path === '' || !matchesRule(host, path)) return host
  return `${host}${path.slice(0, MAX_PATH_KEY_LENGTH)}`
}