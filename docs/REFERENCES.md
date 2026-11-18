# External repositories — evaluation for mailshieldv1

Principle: keep the engine offline, dependency-light, and AppSec-first. Prefer
ideas and later optional adapters over vendoring large suites.

| Repository | What it is | Fit for mailshieldv1 | Decision |
|------------|------------|----------------------|----------|
| [elceef/dnstwist](https://github.com/elceef/dnstwist) | Domain permutation / lookalike detection | Useful for brand impersonation **after** URL extract; often implies DNS | **Later optional**: offline permutation hints only; do **not** add live DNS into the core engine |
| [rf-peixoto/phishing_pot](https://github.com/rf-peixoto/phishing_pot) | Phishing sample corpus for research | Useful as **external** corpus inspiration | **Do not vendor** live phishing into git; may curate **synthetic** cases inspired by patterns |
| [microsoft/MHA](https://github.com/microsoft/MHA) | Outlook Message Header Analyzer | Closest product analog for header storytelling | **Inspiration only** (already covered by headers analyzer + HTML report) |
| [DidierStevensSuite](https://github.com/DidierStevens/DidierStevensSuite/tree/master) | PDF/OLE/forensic utilities | Strong fit for **attachment** deep-dives | **Later** attachments phase — call as optional tools or reimplement minimal static checks |
| [Matmaus/LnkParse3](https://github.com/Matmaus/LnkParse3) | Windows `.lnk` parser | Useful when `.lnk` attachments appear | **Later** attachments analyzer dependency/optional extra |
| [A-poc/BlueTeam-Tools](https://github.com/A-poc/BlueTeam-Tools) | Curated blue-team tool list | Reference bookmark | **Docs only** — not embedded |
| [vasilerevnic/certdroid](https://github.com/vasilerevnic/certdroid) | Magisk module for proxy CA on Android | Unrelated to local `.eml` analysis | **Out of scope** |
| [awesome-osint-arsenal](https://github.com/rawfilejson/awesome-osint-arsenal#1-username--social-media-osint) | OSINT link collection | Enrichment outside the engine | **Out of core** (optional analyst playbook later) |
| [DeHashed-API-Tool](https://github.com/hmaverickadams/DeHashed-API-Tool) | Breach-lookup API client | Needs network + API keys | **Out of scope** for offline engine |

## What we added now (coherent)

- Static **URL extraction** + **SOC defanging** (`hxxps[://]`, `[.]`) in-report and via `-f urls`
- Light URL findings (IP literal host, userinfo spoof) with **no fetching**
- **Analyst pivots** (click-to-open, optional): [Unshorten.it](https://unshorten.it/),
  [DomainTools WHOIS](https://whois.domaintools.com/),
  [PhishTank](https://phishtank.org/),
  [dnstwist.it](https://dnstwist.it/),
  [MXToolbox Email Headers](https://mxtoolbox.com/EmailHeaders.aspx) / SuperTool

## Pivot design

| Tool | How we use it |
|------|----------------|
| Unshorten.it | Primary shortcut for short links (`?shortURL=`). Engine never expands URLs itself. |
| DomainTools WHOIS | Deep-link `whois.domaintools.com/<domain>` for sender + URL hosts |
| PhishTank | Search pivot for URL / domain |
| dnstwist.it | Lookalike domain investigation pivot |
| MXToolbox | Email Headers page + SuperTool MX action for domains |

## What we explicitly did not add

- Live dnstwist / DeHashed / OSINT HTTP inside the core analyzers (optional DNS TXT/A is
  gated behind `--online` only; still no URL fetching)
- Calling Unshorten.it / PhishTank APIs from Python (analyst clicks only)
- Android / Magisk tooling
- Bulk third-party phishing binaries in `samples/`
