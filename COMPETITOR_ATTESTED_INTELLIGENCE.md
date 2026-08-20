# Competitive Assessment: Attested Intelligence

**Date:** 2026-08-20 · **Analyst note:** every claim below is cited. "Verified" = confirmed at an independent source (USPTO, npm, GitHub, Wayback). "Inferred" = reasoned from evidence, not directly observed.

## Verdict

**Early but real — a technically serious, single-operator company with no customers, no funding, and cooling momentum. Confidence: high on facts, moderate on trajectory.**

This is not a landing-page shell. Real shipped code, a real non-provisional patent filing, a real LLC and trademark. It is also, on all available evidence, **one pseudonymous developer** with zero external validation.

## Evidence

### Verified

| Fact | Source |
|---|---|
| Entity: Attested Intelligence Holdings LLC, Illinois File No. 17233815 | [/provenance](https://attestedintelligence.com/provenance) (self-asserted; IL SOS search timed out) |
| TM "ATTESTED INTELLIGENCE" SN 99677085 filed **2026-03-02**, owner Attested Intelligence Holdings LLC, 333 W Bethalto Dr Ste C **#113**, Bethalto IL — **no attorney of record** | [TSDR](https://tsdr.uspto.gov/statusview/sn99677085) |
| TM status: **suspended** by Office action, 2026-07-13 | TSDR (above) |
| npm `@attested-intelligence/aga-mcp-server`: first publish **2026-03-05**, latest **3.3.3 on 2026-07-03**, MIT | [registry.npmjs.org](https://registry.npmjs.org/@attested-intelligence/aga-mcp-server) |
| npm downloads: May 121 · Jun 1,191 · Jul 843 · Aug(19d) 163 — **declining post-June** | [api.npmjs.org](https://api.npmjs.org/downloads/range/2026-05-01:2026-08-19/@attested-intelligence/aga-mcp-server) |
| PyPI `aga-governance` 0.2.6, last release **2026-07-04**, 4 versions total | [pypi.org](https://pypi.org/pypi/aga-governance/json) |
| GitHub `attestedintelligence` is a **USER, not an org** — 1 public repo, **0 followers**, created 2025-12-25 | [api.github.com](https://api.github.com/users/attestedintelligence) |
| Repo `aga-mcp-server`: **0 stars, 0 forks, 0 watchers, 0 open issues**; created 2026-06-08, last push 2026-07-31 | [api.github.com](https://api.github.com/repos/attestedintelligence/aga-mcp-server) |
| **Exactly one contributor**, `neuro-crypt` (48 commits, `neurocrypt@outlook.com`); account has 0 public repos, 0 followers, no name/bio | [contributors](https://api.github.com/repos/attestedintelligence/aga-mcp-server/contributors) |
| Last commit **2026-07-03** (~7 weeks ago) | [commits](https://api.github.com/repos/attestedintelligence/aga-mcp-server/commits) |
| Blog: 16 posts, 2026-03-11 → **2026-05-01, then silence (3.5 months)**; no bylines | [/blog](https://attestedintelligence.com/blog) |
| Site first archived **2026-01-10**; last snapshot 2026-08-05 | [Wayback CDX](http://web.archive.org/cdx/search/cdx?url=attestedintelligence.com&output=json) |
| Founder self-named: **"Founded by Jack Brennan. Based in the United States."** | [/about](https://attestedintelligence.com/about) |
| No `/pricing`, no `/team`, no `/security` (all 404). Live: `/spec`, `/docs`, `/verify`, `/evaluate`, `/contact`. Working gateway + verifybundle.com (both HTTP 200) | direct fetches |
| Both npm packages are the maintainer's **only** published packages | [npm search](https://registry.npmjs.org/-/v1/search?text=maintainer:attestedgovernance) |

### Not found (and where I looked)

- **Funding:** none. Crunchbase, web search — not found.
- **Team beyond one person:** not found. No LinkedIn company page or employee profiles.
- **"Jack Brennan" independent footprint:** **not found.** No LinkedIn, no conference talk, no prior art, no press. The name appears only on their own About page and nowhere else on the open web. It does not link to the pseudonymous `neuro-crypt` commit identity.
- **Customers/testimonials/logos:** none anywhere — their site or third-party.
- **Press coverage, job postings, social accounts, Show HN, Reddit:** not found.
- **Third-party mentions:** only [Glama](https://glama.ai/mcp/servers/attestedintelligence/aga-mcp-server), an automated MCP directory that scrapes npm/GitHub. Not an endorsement.

## The Patent

**Application 19/433,835, "Systems and Methods for Generating and Attested Governance Artifacts," filed 2025-12-28** (title/date self-asserted on [/about](https://attestedintelligence.com/about)).

**Its text is NOT public yet, and will not be until roughly 2027-06-28** (18-month publication). Verified: Google Patents returns **0 results** for the assignee ([xhr query](https://patents.google.com/xhr/query?url=q%3D%22attested+intelligence+holdings%22)). USPTO Patent Center serves a JS shell to scripted fetches; the ODP API returned 401 (key required). I could not read the file wrapper. **Anything about the claims is unknowable right now — treat all claim-scope talk as unverifiable.**

**Inferred, and important:** the `19/` series code is USPTO's current **non-provisional utility** series. Provisionals are `63/`. So this is very likely a **full non-provisional, not a provisional** — contradicting our founder's hypothesis. That means a real spec with real claims and a real examination path, filed at real cost. However, **no attorney of record on the trademark** suggests pro se filing throughout; a self-drafted non-provisional is common and often yields narrow claims.

## Three facts that would most change the verdict

1. **The actual claim scope.** → USPTO Patent Center file wrapper (`patentcenter.uspto.gov`, needs a browser session or an [ODP API key](https://api.uspto.gov)), or wait for publication ~June 2027. Broad granted claims on "seal-capture-prove" would be the single biggest threat to us.
2. **Whether a real funded team exists behind "Jack Brennan."** → Illinois SOS entity search for File No. 17233815 (registered agent + manager names), and the regulations.gov comment **NIST-2025-0035-0211** (submitter names are public; returned 403 to scripted fetch — try a browser).
3. **Any paying design partner, especially in defense/SCADA.** → SAM.gov, USAspending, and DoD SBIR award databases. Their positioning is defense-heavy; an SBIR award would flip this from hobby-scale to funded.

## Implication for DarkMatter

- **Priority date: they are AHEAD.** 2025-12-28 non-provisional is a hard date we cannot beat. This is the one axis where they have durable advantage — and the only one that should change our behavior. Get our own filing dated, and have counsel assess design-around and prior-art once their text publishes.
- **Technology: roughly LEVEL.** Their engineering is disciplined (371-test suite, multi-toolchain verifiers, SLSA provenance, CI security gates — visible in commit history). Do not dismiss it. But it is one person's output, and the commit style suggests heavy AI assistance, which we can match.
- **Distribution and customers: they are BEHIND.** 0 GitHub stars, ~250 monthly npm downloads (much of it likely CI/mirrors), no customers, no funding, no pricing page, no way to sign up. They have no distribution advantage whatsoever.
- **Momentum: cooling.** Blog dead since May 1, code quiet since July 3. Consistent with a solo founder who shipped hard for four months and has slowed — possibly to pursue the patent, possibly stalling.

**Strategic read:** compete on distribution, customers, and self-serve product — where they are weakest and slowest. Treat the patent as the one genuine risk and handle it legally, not competitively. Do not treat them as a funded rival; do not dismiss them as vapor.
