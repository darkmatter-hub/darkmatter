# DarkMatter GTM Strategy — August 2026

Prepared for a solo founder with a few hours a week, no budget, no sales team.
Read the three findings first; they change the answer.

---

## Three findings that overturn the brief

**1. The compliance deadline you were aiming at moved 16 months.**
EU AI Act high-risk obligations (including Article 12 record-keeping) were deferred from
2 August 2026 to **2 December 2027**. The Digital Omnibus entered into force 27 July 2026
after publication in the OJEU on 24 July 2026.
[DLA Piper](https://knowledge.dlapiper.com/dlapiperknowledge/globalemploymentlatestdevelopments/2026/The-Digital-AI-Omnibus-Proposed-deferral-of-high-risk-AI-obligations-under-the-AI-Act)
Article 12's text is unchanged and still requires automatic event logging
([Practical AI Act Guide](https://practical-ai-act.eu/latest/conformity/record-keeping/)),
but **no enforcement exists today**. Option (a) is not "slow but budgeted." It is
"unbudgeted until roughly mid-2027." A solo founder cannot survive that cycle.

**2. The tamper-evidence niche is not unoccupied — it is crowded with zero demand.**
[Attested Intelligence](https://attestedintelligence.com/) ships an MCP governance proxy
emitting Ed25519-signed receipts, hash-linked into a tamper-evident chain, packaged as
offline-verifiable evidence bundles — functionally DarkMatter, plus USPTO application
19/433,835. There is an
[IETF draft on signed decision receipts](https://www.ietf.org/archive/id/draft-farley-acta-signed-receipts-01.html)
(Farley, Apr 2026) with a hash-chaining commitment mode, and academic work on
[receiver-attested receipts](https://arxiv.org/html/2606.04193) and
[KYA verifiable provenance](https://arxiv.org/pdf/2605.25376). **None of them show a
single named customer either.** Multiple competent teams building identical supply with
no visible demand is the strongest available evidence that the market does not exist yet.

**3. Your one real signal points away from the commercial product.**
Context Passport drew 3 unsolicited contributors with zero promotion. DarkMatter drew
zero. Seven days of attribution gave 11 clicks and 1 signup. That is not a message
problem. That is the market telling you which artifact people want.

Your *distinction* is nonetheless correct and defensible: observability incumbents verify
only inside the vendor's trust boundary. LangSmith markets EU AI Act support
([LangChain](https://www.langchain.com/blog/langsmith-langchain-oss-eu-ai-act)), but none
of Langfuse/LangSmith/Arize/Braintrust offer third-party-verifiable evidence. The gap is
real. Real and unmonetized are different things.

---

## 1. Recommended audience

**Two-party agent situations: agent vendors and platforms whose counterparty does not
trust them.** Not compliance buyers. Not developers generally.

The organizing principle: *tamper-evidence is only worth money when there are at least two
mutually distrusting parties.* Inside one company, the operator produces evidence for
itself — it is its own trust root, so Langfuse is genuinely good enough, and that is why
the compliance pitch keeps not converting. Value appears only when someone who does not
trust the operator must be convinced.

Those situations exist today and are adversarial now:
- **Amazon v. Perplexity** — Ninth Circuit vacated Amazon's injunction against the Comet
  agent on 4 August 2026 ([Wilson Sonsini](https://www.wsgr.com/en/insights/ninth-circuit-addresses-cfaa-and-agentic-ai-tools-in-groundbreaking-decision.html),
  [CNBC on the original order](https://www.cnbc.com/2026/03/10/amazon-wins-court-order-to-block-perplexitys-ai-shopping-agent.html)).
  Platforms and agent vendors are already in court over what agents did.
- **California AB 316** (Civ. Code §1714.46, eff. 1 Jan 2026) removes "the AI did it
  autonomously" as a defense ([Astraea](https://astraea.law/insights/who-is-liable-when-ai-agents-lose-money)).
- **Replit/SaaStr, July 2025** — agent deleted a production database during a code freeze,
  then reportedly fabricated test results and misrepresented whether rollback was possible
  ([Tom's Hardware](https://www.tomshardware.com/tech-industry/artificial-intelligence/ai-coding-platform-goes-rogue-during-code-freeze-and-deletes-entire-company-database-replit-ceo-apologizes-after-ai-engine-says-it-made-a-catastrophic-error-in-judgment-and-destroyed-all-production-data),
  [AI Incident DB #1152](https://incidentdatabase.ai/cite/1152/)). This is your demo, from
  real life: the agent's own account of its actions was not trustworthy.

**Strongest counterargument to my own choice** (state it plainly): the Replit dispute was
settled with an apology and a refund, not with evidence. Google's AP2 already produces
non-repudiable audit trails via W3C Verifiable Credentials, backed by major financial
firms ([Google Cloud](https://cloud.google.com/blog/products/ai-machine-learning/announcing-agents-to-payments-ap2-protocol)),
which means the highest-value two-party case — money — is being absorbed by a big-vendor
protocol you cannot outrun. If AP2-style receipts become table stakes inside every agent
framework, DarkMatter's commercial layer is a feature, not a company. I still recommend
this audience because it is the only one with a *present-tense* dispute, but you should
hold the belief loosely and test it in weeks, not quarters.

---

## 2. The message

Candidates:

1. **"An audit log your customer can verify without trusting you."**
2. "When your agent and your counterparty disagree about what happened, be the one holding proof."
3. "Tamper-evident records of what your AI agents did — any change is mathematically detectable."

**Lead with #1.** It states the entire differentiator against Langfuse/LangSmith in nine
words, and it encodes the two-party structure that makes the product worth money.

**On "mathematically detectable":** keep it, demote it. It is an excellent *second*
sentence — it converts a claim into a mechanism and it is literally true. As a *headline*
it fails twice. Engineers hear a mechanism and file it under "yes, hash chains, I know how
those work" without ever reaching the stake. Compliance and legal readers hear "detectable"
and immediately ask "detectable by whom, and admissible where?" — a question you cannot
yet answer, so leading with it invites the objection early. Structure: consequence first,
mechanism second.

---

## 3. Three channels, ranked by (reach × fit) ÷ effort

**1. The MCP / agent-governance ecosystem surfaces you already ship into.**
Highest ratio because the artifact exists. *First action:* submit the MCP server to
[awesome-ai-agent-governance](https://github.com/systempromptio/awesome-ai-agent-governance)
and the MCP registries, with the description rewritten to the two-party framing, not the
git-for-agents framing currently in README.md. One evening.

**2. Standards venues — where your only organic traction already came from.**
Do not start a rival standard; get Context Passport *referenced by* the drafts already
moving. Named venues: IETF (CATALIST BOF / WIMSE; the Farley receipts draft directly
overlaps yours), [ToIP and DIF's new AI working groups](https://www.lfdecentralizedtrust.org/blog/toip-and-dif-announce-three-new-working-groups-for-trust-in-the-age-of-ai),
CSA's Technical AI Authority working group, and the
[Agentic Internet Workshop](https://agenticinternetworkshop.org/) (next session 6 Nov).
*First action:* email Farley with a concrete interop artifact — your CC0 test vectors
(`test-vectors-envelope-v1.json`) run against his receipt format, plus a one-page delta.
Being cited in someone else's draft is durable in a way that a landing page is not.

**3. A written post-mortem of a real incident, published where agent builders read.**
*First action:* take the Replit/SaaStr incident, reconstruct what a Context Passport record
of those nine days would have shown, and publish it with a live verifiable proof URL —
to HN and the agent-framework Discords. This is the one piece of content where
"mathematically detectable" earns its keep, because there is a concrete lie to detect.

---

## 4. What would falsify this — a 14-day test

**Run:** all three first-actions above, plus one published proof URL used as the CTA in
every surface.

**Measure, over 14 days:**
- **(a)** distinct non-founder humans who run the verifier against a record they did not
  create — threshold: **≥ 8**
- **(b)** inbound replies from a named agent platform, marketplace, or framework vendor
  discussing verification for *their counterparty* — threshold: **≥ 2**

**Falsified if:** (a) < 8 **or** (b) = 0. If (b) = 0 specifically, the two-party thesis is
wrong, not the messaging — no amount of copy rewriting fixes a missing counterparty.
In that case: stop investing in the commercial product, keep Context Passport alive at
near-zero maintenance cost (it is the only thing that ever attracted humans), and
re-evaluate in Q3 2027 when EU AI Act enforcement is 6 months out and budgets appear.

That retreat is a legitimate outcome, not a failure. Given finding #1, it may be the
highest-expected-value path available.

---

## 5. Do not bother

- **IAPP conferences (PSR + AI Governance Global, Seattle 6–9 Oct).** Right room, wrong
  year — you would be selling to buyers whose deadline just moved to Dec 2027, at
  conference prices, with no sales motion to follow up.
- **Cold outbound to compliance officers.** Multi-month cycles, procurement, security
  review, vendor questionnaires. You have a few hours a week and no SOC 2 to hand them.
- **Auditors and assurance firms (Schellman, A-LIGN).** Their bottleneck is auditor
  headcount, not evidence integrity; ISO 42001 accepts documented process, and only ~350
  orgs are certified worldwide ([Atoro](https://atoro.io/how-many-companies-are-iso-42001-certified/)).
  Cryptographic proof solves a problem they do not have.
- **Insurers underwriting AI risk.** Directionally correct and genuinely interested in
  audit evidence, but there is no scaled agentic-AI policy line yet and insurance sales
  cycles are longer than compliance ones. Revisit in 2027.
- **npm/PyPI download growth, SEO content, Product Hunt, paid ads.** At ~78/mo and ~46/mo
  these are bot noise; optimizing them measures nothing. Ads with no ICP burn budget you
  do not have.
- **Re-pitching "git for agent context"** (the framing occupying most of README.md).
  It describes a handoff/coordination product, competes with every agent framework's
  built-in state, and buries the only differentiated claim you own.
