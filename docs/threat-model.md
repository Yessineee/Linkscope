# Linkscope threat model

Linkscope is a browser extension that warns users about phishing pages. This
document asks one question: how does each attacker defeat, abuse, or leak data
through Linkscope itself? Status is updated as fixes land.

## Assets to protect

- The user's browsing history (scan history, link checks, API result cache).
- The user's API keys.
- The integrity of the verdict and of the warning the user sees.

## 1. Phishing operator

Goal: collect credentials without being flagged.
Controls: the domain name, the page content and forms, redirects, and the
hosting platform.

| Attack on Linkscope | Evidence | Status |
|---|---|---|
| Trailing-dot hostname (`paypa1.com.`) hides the lookalike | test: trailing dot | Fixed |
| Brand name on the wrong suffix, in a subdomain, or on a shared host (`paypal.github.io`) | tests: brand impersonation | Fixed |
| Subdomain named `10` triggers the private-address skip | test: subdomain named "10" | Fixed |
| Multi-part public suffixes parsed wrongly (`.com.ng`) | test: multi-part public suffix | Fixed |
| Legitimate IDNs flagged as homograph attacks | test: legitimate IDN | Fixed |
| Fully non-Latin lookalike of a brand name | none yet | Open (needs a Unicode confusables table) |
| Form field named `action` crashes the content script and skips analysis | manual test page | Fixed in code, manual test pending |
| API outage cached as "safe" for 24 hours | manual test | Fixed (shown as "could not verify", re-checked after 5 minutes) |
| Cache and whitelist keyed by hostname, so one verdict covers every page on a multi-tenant host (Google Forms, Sites) | tests: cache key | Fixed for a curated list of hosts; other hosts still    share one verdict per hostname |
| Redirect-chain tracking likely sees too few hops | none yet | Open |
| Verdict can arrive late (VirusTotal polling takes up to ~30 s) | service worker log; manual test with a simulated VirusTotal result | Fixed (progressive verdict) |
| A slow or hanging data source holds up the fast verdict | none yet | Open (request timeouts planned) |
| Analysis depends on the content script running | none yet | Fixed in code (analysis starts at navigation commit; page signals are added when the content script reports); manual test pending |
| Single-page-app navigations are not rescanned | none yet | Fixed (10 s request timeouts) |

## 2. Malicious page

Goal: make the user ignore or never see the warning.
Controls: everything in the page's own DOM.

| Attack on Linkscope | Evidence | Status |
|---|---|---|
| Warning overlay lives in the page DOM: the page can remove it, cover it, or click "Continue anyway" | none yet | Open (interstitial page planned) |
| DOM clobbering of form properties | manual test page | Fixed in code, manual test pending |
| Page-supplied data trusted by the worker | code review | Fixed (only strict booleans accepted; HTTPS taken from the tab URL) |
| Late verdict shown on the wrong page after navigating or rescanning | manual test | Fixed (tab URL check); rescan case fixed in code, test pending |
| Stale verdict shown in the popup | manual test | Fixed |

## 3. Privacy leakage (the leaker is Linkscope)

Concern: browsing data reaching parties the user didn't intend.

| Issue | Status |
|---|---|
| Full URLs, including paths and query strings, are sent to Google Safe Browsing, IPQualityScore, and VirusTotal | Open |
| The dashboard and exported reports request favicons from Google, so visited domains reach Google | Fixed (local favicon cache; reports contain no favicons) |
| Whitelisted sites were still sent to the APIs | Fixed |
| "Clear History" leaves the API cache and link checks in place | Fixed ("Delete all scan data" clears history, link checks, caches and per-tab results) |
| API keys in extension storage are readable from content scripts | Open |
| The dashboard page can be framed by any website | Fixed |

## Known limitations

- If the browser stops the extension's background worker while a scan is running,
  that scan leaves no history entry or cache entry, and the next visit rescans.
- The VirusTotal free tier allows 4 lookups per minute and 500 per day. Its terms
  restrict commercial use, so any public release should use keys supplied by the
  user, never a shared one.
- VirusTotal lookups send the full URL, including path and query string (see the
  privacy table above).
- Pages where the content script doesn't run (for example the PDF viewer) get a
  popup verdict and a notification for dangerous results, but no in-page warning.
- If the content script reports later than a few seconds after load, the verdict
  is raised but the history entry keeps the earlier score.
- IPQualityScore's risk score for the same URL can change between lookups, and the
  scorer adds its points only above 75, so sites near that threshold can flip
  between Safe and Suspicious. Weights will be calibrated against measured data.
- The list of multi-tenant hosts is curated by hand and incomplete. A multi-tenant
  host that isn't on it shares one cached verdict, and one whitelist entry, per hostname.

## Out of scope

- ClickFix and fake-CAPTCHA social engineering that tricks the user into running
  commands.
- Malware in downloaded files (a separate project handles file scanning).
- Scams and pop-ups that don't involve a URL or page content Linkscope can see.
- Keyloggers and other malware already running on the user's machine.
- Attacks on the browser itself.