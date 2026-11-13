# Local detection: offline evaluation

Measured on 2026-11-11 with `npm run eval`. This covers only the checks that work without
any outside service: the lookalike and impersonation rules on the address, plus the plain-HTTP
signal. The three lookup APIs and the page-content signals are not part of it.

## Data

- Phishing addresses: Phishing.Database active links (MIT license) and the OpenPhish community
  feed (non-commercial use only). The OpenPhish feed gave only 300 addresses, so results are
  effectively Phishing.Database results. Sample: 5,000 addresses, at most 3 per domain.
- Legitimate domains: the Tranco list, as `https://domain/`. Two groups: the top 1,000, and
  5,000 random domains ranked below 10,000.
- The data is not committed. Addresses were only parsed as text, never visited.

## Results (two samples)

| | Seed 42 | Seed 7 |
|---|---|---|
| Phishing caught, any warning | 2.8% | 2.8% |
| Phishing caught, overlay | 0.7% | 0.7% |
| False alarms per 1,000, top 1,000 sites | 23.0 | 23.0 (same set) |
| False alarms per 1,000, long tail | 2.8 | 1.8 |

About 74% of missed phishing addresses were ordinary domains and 24% were on shared hosting.

## What this means

- Address-only local checks catch a small share of phishing. Most phishing domains contain
  no brand name, so the lookup services and the blocklists behind them do almost all the work.
- The top-sites false alarms are mostly other domains owned by the same brands
  (`facebook.net`, `adobe.io`, `google.com.hk`) and infrastructure domains that people do not
  type into a browser.
- The long-tail rate is an upper bound: Tranco membership is not proof of legitimacy.

## Limits

- Legitimate addresses were root domains over HTTPS, so path-based rules cannot be evaluated.
- The phishing list is automatically assembled and may include stale or mislabeled entries.
- Two samples are small; the long-tail counts (14 and 9) are within sampling noise.