# Manual tests still pending

| Test | How | Expected | Done |
|---|---|---|---|
| Form field named `action` | Host a page with a form containing `<input name="action">` and a password field, with the form posting to another domain | Popup lists the suspicious-form signal | no |
| Protocol-relative form action | Same page, with `action="//other.example/post"` | Same signal | no |
| Page without a content script | Open a public PDF | Popup shows a verdict | no |
| Overlay on a slow page | Throttle to Slow 3G, open `https://paypal.github.io/` | Overlay appears once the page loads | yes |
| Notification path | Set thresholds to 10, 20, 40, then run the VirusTotal stub test | Dangerous result, one notification, one overlay | yes |
| Per-page whitelist | On a Google Form or Sites page, whitelist it from the popup, reload it, then open another form | First page shows "Whitelisted", second is still scanned | yes |
| Query stripped from lookups | Open a page with a query string, check the service worker Network tab | No query string in the IPQS request | no |
| First-party skip | Open Gmail | Console: No external lookups (brand-owned) | yes |
| Local-only mode | Turn it on, open a new site | No outside requests; popup shows the note | yes |
| Redirect chain | Open the nested httpbin redirect URL | Popup lists the redirect-chain signal | no |
| Single-page app routes | Click through several pages on github.com | One scan line per route; popup shows the current URL | no |
| Storage from content script | Run the key-names line in the content script console | Error or empty list | yes |