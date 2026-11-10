import { ALLOWED_DOMAINS, COUNTRY_VARIANT_BRANDS, COMMON_COUNTRY_CODES, USER_CONTENT_DOMAINS } from './brands.js'

// True for a brand's own domains, including its country variants (google.fr, amazon.co.uk),
// but never for a label on a shared host (google.github.io).
export function isBrandOwnedHost(parsed) {
  if (ALLOWED_DOMAINS.has(parsed.registrableDomain)) return true
  if (COUNTRY_VARIANT_BRANDS.has(parsed.domainLabel) && !parsed.onSharedHost) {
    const countryCode = parsed.publicSuffix.split('.').pop()
    return COMMON_COUNTRY_CODES.has(countryCode)
  }
  return false
}

// A brand's own pages, as opposed to places where other people publish pages
// (blogs, shared designs, file shares).
export function isFirstPartyHost(parsed) {
  return isBrandOwnedHost(parsed) && !USER_CONTENT_DOMAINS.has(parsed.registrableDomain)
}