# Manual tests still pending

| Test | How | Expected | Done |
|---|---|---|---|
| Form field named `action` | Host a page with a form containing `<input name="action">` and a password field, with the form posting to another domain | Popup lists the suspicious-form signal | no |
| Protocol-relative form action | Same page, with `action="//other.example/post"` | Same signal | no |
| Page without a content script | Open a public PDF | Popup shows a verdict | no |
| Overlay on a slow page | Throttle to Slow 3G, open `https://paypal.github.io/` | Overlay appears once the page loads | no |
| Notification path | Set thresholds to 10, 20, 40, then run the VirusTotal stub test | Dangerous result, one notification, one overlay | no |