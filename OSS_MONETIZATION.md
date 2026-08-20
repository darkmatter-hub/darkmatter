# Does a CC0 Standard Monetize?

Answering: *"We can pivot to Context Passport if DarkMatter is still not a product for
another 16 months, but how does this pivot help monetize when Context Passport is free
and open source?"*

---

## 1. The direct answer

Close to a category error, but not quite. Standards never monetize. Standards *authors*
sometimes do, by owning something adjacent that adoption makes valuable. Every mechanism
below requires adoption you do not have, capital you do not have, or a mandate that does
not exist.

| Mechanism | Example | Available solo, no capital? |
|---|---|---|
| Open-core SaaS on the standard | Grafana, Sentry, dbt | In principle. In practice needs distribution you lack |
| Relicense the implementation later | Redis, HashiCorp, MinIO | **No.** Works only from incumbency |
| Operate the neutral third party | Certificate Transparency logs | **No.** CT logs are cost centres, not products |
| Monitor/verify on top of someone's standard | SSLMate Cert Spotter | **Yes.** The only clean fit |
| Certification / conformance mark | Khronos Adopters (~$20K/spec) | **No.** Needs implementers with budgets |
| Adjacent product the standard makes credible | Chainguard (sigstore authors) | **No.** $612M raised to reach $40M ARR |
| Foundation / sponsorship | ISRG, $9.56M revenue FY2024 | **No.** Needs existential criticality |
| The standard as a career credential | Lightstep, Chainguard founders | **Yes.** Real, and undervalued here |

The load-bearing insight: **the asset is never the standard, it is the mandate behind it.**
CT monetizes because Chrome refuses to trust non-logged certificates. Let's Encrypt exists
because browsers forced HTTPS. Context Passport has no forcing function until December
2027 at the earliest, and Article 12 does not name a format even then. A standard with no
enforcer is a schema.

## 2. Comparables

**Cases where the standard's author did NOT capture the value.** This is your actual risk.

- **OpenTelemetry / Lightstep.** Lightstep staff co-created OpenTracing and OpenTelemetry.
  ServiceNow bought Lightstep for ~$510M ([MarketScreener](https://www.marketscreener.com/quote/stock/SERVICENOW-INC-10912979/news/ServiceNow-Inc-completed-the-acquisition-of-LightStep-Inc-for-approximately-510-million-36121459/)).
  Datadog, which authored nothing, did **$3.4B revenue in FY2025**
  ([Datadog IR](https://investors.datadoghq.com/news-releases/news-release-details/datadog-announces-fourth-quarter-and-fiscal-year-2025-financial/))
  and sells OTel ingestion as a feature. The authors got a mid-size exit; the incumbent got
  the market.
- **Docker.** Created the container format, donated runc to OCI, then sold Docker
  Enterprise to Mirantis in 2019 on undisclosed terms
  ([TechCrunch](https://techcrunch.com/2019/11/13/mirantis-acquires-docker-enterprise/)).
  Mirantis was running >$100M off those assets two years later
  ([TechCrunch](https://techcrunch.com/2022/02/09/mirantis-on-run-rate-over-100m-two-years-after-buying-docker-enterprise-assets)).
- **Certificate Transparency.** Authored at Google, RFC 6962. Google monetized none of it.
  The money went to a monitoring layer: SSLMate's Cert Spotter sells at $15 to $500/month
  ([pricing](https://sslmate.com/certspotter/pricing)), operated by Opsmate Inc., founded
  2014, deliberately customer-funded and never VC-backed ([about](https://sslmate.com/about/)).
  Censys, adjacent, raised $201M ([PR](https://www.prnewswire.com/news-releases/censys-secures-75m-in-new-funding-301965193.html)).
- **OpenTimestamps.** The closest analog to your primitive: free, trust-minimized,
  tamper-evident timestamping ([Peter Todd](https://petertodd.org/2016/opentimestamps-announcement)).
  Never a business, by design. Tierion tried to commercialize the same primitive via
  Chainpoint, raised ~$25M in an ICO
  ([CoinDesk](https://www.coindesk.com/markets/2017/07/28/25-million-blockchain-startup-tierion-completes-ico-for-tnt-token)),
  and settled with the SEC in 2020: return funds, $250K penalty, disable trading
  ([SEC](https://www.sec.gov/enforcement-litigation/administrative-proceedings/33-10914-s)).
  **Tamper-evidence as a paid product has a poor track record independent of AI.**

**Cases where it worked, and what it cost.**

- **Chainguard.** Sigstore's authors, including Dan Lorenc, left Google and founded it in
  2021. Revenue comes from hardened container images, *not* sigstore
  ([Contrary](https://research.contrary.com/company/chainguard)). $612M raised across five
  rounds to reach ~$40M ARR at a $3.5B valuation
  ([GeekWire](https://www.geekwire.com/2025/cybersecurity-startup-chainguard-lands-356m-now-valued-at-3-5b/)).
  Four years, nine figures of capital, and the money came from something adjacent.
- **Grafana Labs.** $425M ARR, $805M raised, ten years
  ([Grafana](https://grafana.com/press/2025/09/30/grafana-labs-surpasses-400m-arr-and-7000-customers-gains-new-investors-to-accelerate-global-expansion/)).
- **Sentry.** $100M ARR on $217M raised, relicensed away from open source to do it
  ([Sacra](https://sacra.com/c/sentry/), [Sentry](https://blog.sentry.io/sentry-is-now-fair-source/)).
- **dbt Labs.** Apache-2.0 core, $4.2B valuation, ultimately merged into Fivetran in 2026
  ([Fivetran](https://www.fivetran.com/press/fivetran-dbt-labs-complete-merger-to-create-the-data-infrastructure-for-trusted-ai-agents)).
- **ISRG / Let's Encrypt.** Nonprofit. FY2024 revenue $9,563,960 against $7,925,896 expenses,
  from corporate sponsorship ([ProPublica](https://projects.propublica.org/nonprofits/organizations/463344200)).
  Zero of it from the standard.

**Zero cases in this list reached revenue without either eight-figure capital or a mandate.
The single exception, SSLMate, monetizes a standard it did not write, enforced by Chrome.**

## 3. What is actually defensible

**Real:**
- *The trusted-third-party role.* Genuinely the point of a verification product, and
  genuinely valuable. But note what CT actually did: it solved neutrality with **multiple
  independent logs plus auditors**, not one trusted vendor. A for-profit verifier owned by
  the spec author is not neutral, and a better-funded entrant with a recognizable brand
  beats an unknown solo operator at precisely this game, because the asset is reputation.
- *Authorship as a credential.* Lorenc and Sigelman both converted standard authorship into
  a company or a job. This is the most reliable payoff in the entire dataset.
- *Hosted convenience.* Real but small and commoditized. Attested Intelligence already
  ships this shape.

**Stories founders tell themselves:**
- *Certification marks.* Khronos charges ~$20K per adopter, and only can because Adopters
  ship GPUs ([Khronos](https://www.khronos.org/conformance/adopters)). At 0 stars there is
  nobody to certify. Your conformance suite is good engineering, not revenue.
- *Registry / namespace control.* CC0 means the namespace forks the moment it is worth
  forking. Terraform's BSL move produced OpenTofu in two weeks
  ([SDxCentral](https://www.sdxcentral.com/news/ibm-acquires-hashicorp-for-64b-open-source-terraform-questions-remain/)).
  Redis's licence change produced Valkey, now the default in Debian, Ubuntu and Fedora.
- *Data network effects.* There are none. Signed hash chains are per-customer and opaque.
  Nothing gets smarter with more customers.
- *Relicense later.* Redis and MinIO show this works only from incumbency, and MinIO's
  version put the project into maintenance mode
  ([Blocks & Files](https://www.blocksandfiles.com/ai-ml/2025/06/19/minio-users-complain-after-admin-ui-removed-from-community-edition/1610856)).
  Doing it now would cost you the three contributors, which is your only real signal.

## 4. Recommendation

**(a) Push adoption, monetize later.** Cost: ~4 hrs/week for 16+ months. Earns: nothing
until a mandate arrives. Requires: that Article 12 lands with teeth *and* names or implies
your format. Two conditionals, neither in your control.

**(b) Keep pushing DarkMatter.** Cost: full attention. Earns: on current evidence, zero.
Requires: a present-tense buyer. Eleven clicks and no retention over a week says there
isn't one, and multiple funded teams are building identical supply to the same silence.

**(c) Neither is currently a business. Treat both as portfolio assets and earn income
elsewhere.** Cost: ~2 hrs/week maintaining the spec, merging contributor PRs, keeping
releases current. Earns: nothing directly, but preserves the option and builds the
credential that actually paid off for Lorenc and Sigelman.

**I would choose (c), with the §5 test run first.** The evidence is not ambiguous: no
comparable here monetized a standard at your scale without a mandate or nine-figure
capital, and your one genuine signal, three unsolicited contributors, is about the
*artifact's* quality, not anyone's willingness to pay. Sixteen months of unpaid waiting
for a regulation is not a plan, it is a bet on a legislature.

**Strongest argument against my own choice:** if Article 12 does land with real
record-keeping enforcement in December 2027 and no format standard has emerged, being the
author of the one with a governance document, a three-tier conformance suite and
independent contributors is a position a funded competitor cannot buy quickly. Dormancy
loses the three contributors, and contributors are the only thing separating your spec
from a vendor schema. If you pick (c), keep the 2 hrs/week honestly, not nominally.

## 5. The 90-day test

**Run 20 outbound conversations with agent vendors and platforms whose counterparty does
not trust them. Success threshold: one signed LOI or paid pilot at ≥$100/month, or one
unsolicited third-party implementation listed in `IMPLEMENTATIONS.md` by an organisation
you have no relationship with.**

The $100 figure is not invented. It is SSLMate's Startup tier price
([pricing](https://sslmate.com/certspotter/pricing)), the demonstrated market rate for
third-party verification monitoring on a transparency standard, set by a profitable,
customer-funded company doing structurally the same job. That business exists because
Chrome *mandates* CT. If nobody will pay the price the market bears for the mandatory
version, the voluntary version does not clear either, and the answer is (c) without
further debate.

Cost of the test: your time, three weeks of writing, no money.
