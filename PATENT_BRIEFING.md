# Patent Briefing: DarkMatter / Context Passport

**Prepared 2026-08-20 for a meeting with a licensed patent attorney.**

> **This is not legal advice.** I am not a lawyer. Nothing here is a freedom-to-operate
> clearance, a validity assessment, or an infringement analysis. Those are attorney
> determinations. Every factual claim carries a URL; inferences are labelled.

---

## 0. What we built

Per `INTEGRITY_SPEC_V1.md` (frozen 2026-04-09) and `context-passport/SPEC.md` v2.0: canonical
JSON (v2 adopts RFC 8785), `SHA-256(canonical(payload))`, an envelope binding
`{schema_version, agent_id, key_id, timestamp, payload_hash, parent_integrity_hash}` hashed to
an `integrity_hash` chained to the parent, optional Ed25519 signature over the *envelope* not
the payload, RFC 6962 Merkle leaf (`SHA-256(0x00 || canonical(leaf))`) with inclusion and
consistency proofs, externally published signed checkpoints, and an offline verifier needing no
vendor trust. Spec is CC0; reference implementations Apache-2.0 (patent grant in section 3).

---

## 1. Is any of this patentable?

**Every primitive is old and public** (section 2), including hash-chained tamper-evident audit
logs specifically, published by Schneier and Kelsey in 1998.

**How software patents fail here.** Under *Alice Corp. v. CLS Bank*, 573 U.S. 208 (2014)
([opinion](https://supreme.justia.com/cases/federal/us/573/208/)), a claim directed to an
abstract idea implemented on generic computing is ineligible under section 101. Closest adverse
authority: *Electric Power Group v. Alstom*, 830 F.3d 1350 (Fed. Cir. 2016)
([opinion](https://law.justia.com/cases/federal/appellate-courts/cafc/15-1778/15-1778-2016-08-01.html)),
holding that collecting, analysing and displaying information is abstract. "Record what an agent
did, hash it, show an auditor" sits close to that.

**What survives.** Claims framed as a concrete technical improvement to machine operation:
*Ancora v. HTC*, 908 F.3d 1343 (Fed. Cir. 2018), assigning a verification structure to BIOS
memory ([case](https://www.bitlaw.com/source/cases/patent/Ancora.html)); *Finjan v. Blue Coat*,
879 F.3d 1299 (Fed. Cir. 2018); *Koninklijke KPN v. Gemalto*, 942 F.3d 1143 (Fed. Cir. 2019),
varying how check data is generated held non-abstract
([summary](https://ipwatchdog.com/2019/11/18/federal-circuit-reverses-district-court-finding-that-check-data-patent-is-abstract/)).
Also [MPEP 2106](https://www.uspto.gov/web/offices/pac/mpep/s2106.html) and the
[2024 AI eligibility update](https://www.federalregister.gov/documents/2024/07/17/2024-15377/2024-guidance-update-on-patent-subject-matter-eligibility-including-on-artificial-intelligence),
Examples 47-49.

**Honest assessment (inference, to test with counsel):** "apply known cryptographic audit
primitives to AI agent actions" is a field-of-use limitation on decades-old art and looks weak
on both eligibility and novelty/obviousness. Anything issuing is likely narrow. Four candidate
angles, none of which I can say are novel:

1. **Dual timestamps:** `accepted_at` binds the Merkle leaf while the client-asserted
   `timestamp` binds the signed envelope.
2. **Envelope-level signing:** one signature authenticating payload, chain position, agent
   identity, key identity, timestamp and schema version together.
3. **Revocation state machine:** `revoked_key` versus `revoked_post_commit`, so integrity
   survives key revocation.
4. **Non-mutating fork lineage:** branching that never modifies the parent chain.

---

## 2. Prior art map (all predates December 2025)

| Reference | Date | Relevance |
|---|---|---|
| [Merkle, US 4,309,569](https://patents.google.com/patent/US4309569A/en) | 1979/1982 | Merkle tree |
| [Haber and Stornetta](https://link.springer.com/article/10.1007/BF00196791) | 1991 | Hash-linked timestamping |
| [Schneier and Kelsey](https://www.usenix.org/legacy/publications/library/proceedings/sec98/full_papers/schneier/schneier.pdf) | 1998 | Tamper-evident audit logs on untrusted machines |
| [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) | 2001 | Trusted third-party timestamps |
| [RFC 4998](https://www.rfc-editor.org/rfc/rfc4998) Evidence Record Syntax | 2007 | Long-term hash-tree evidence records |
| [Crosby and Wallach](https://www.usenix.org/legacy/event/sec09/tech/full_papers/crosby.pdf) | 2009 | History trees, tamper-evident logging |
| [Guardtime KSI, US 8,347,372](https://patents.google.com/patent/US8347372B2/en) | 2013 | Hash-tree signing, published calendar roots |
| **Certificate Transparency, [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) / [9162](https://www.rfc-editor.org/rfc/rfc9162)** | **2013 / 2021** | **Append-only Merkle log, signed tree heads, inclusion and consistency proofs, third-party auditability. Closest structural analogue to our design.** |
| [Google Trillian](https://github.com/google/trillian) | 2016+ | Verifiable log in production |
| [OpenTimestamps](https://opentimestamps.org) | 2016+ | Public-chain anchoring of hash commitments |
| [Amazon QLDB](https://aws.amazon.com/about-aws/whats-new/2019/09/announcing-general-availability-qldb/) | Sep 2019 | Commercial ledger DB, verifiable digests |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) JCS | 2020 | The canonicalisation we use |
| [immudb v1.0](https://immudb.io/blog/immudb-release-1-0) | 2021 | Immutable, verifiable database |
| [Sigstore Rekor](https://github.com/sigstore/rekor) | 2021+ | Public log of signed attestations |
| [in-toto](https://in-toto.io) / [SLSA](https://slsa.dev) | 2019 / 2021+ | Signed provenance for machine-produced artifacts |
| [C2PA Spec 1.0](https://c2pa.org/c2pa-releases-specification-of-worlds-first-industry-standard-for-content-provenance/) | Jan 2022 | Signed, hash-bound provenance manifests any third party can verify, covering AI-generated content |
| **[IETF SCITT drafts](https://datatracker.ietf.org/doc/draft-birkholz-scitt-architecture/)** (later [RFC 9943](https://datatracker.ietf.org/doc/rfc9943/)) | **from 2022** | **Signed statements registered to a transparency service, which returns a verifiable receipt** |
| [IBM, US 11,483,154](https://patents.google.com/patent/US11483154B2/en) | Oct 2022 | Tamper-evident records *of AI system properties* |
| [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model/) | 2019/2022 | Third-party-verifiable signed claims |
| [EU AI Act Arts. 12, 19](https://eur-lex.europa.eu/eli/reg/2024/1689/oj) | 2024 | Creates the requirement, not the mechanism |

**Inference:** CT, SCITT, Rekor and C2PA already publicly combine "canonicalise, hash, sign,
append to a Merkle log, publish signed checkpoints, hand a third party an offline-verifiable
receipt," leaving anyone in this space mainly the AI-agent field of use plus implementation
detail.

---

## 3. The competitor filing: USPTO App. No. 19/433,835

**Verifiable:** the number and "Patent Pending" appear on the company's own
[provenance page](https://attestedintelligence.com/provenance).

**Self-reported, not confirmed against a USPTO record:** title *"Systems and Methods for
Generating and Enforcing Attested Governance Artifacts,"* filed **28 December 2025**, applicant
Attested Intelligence Holdings LLC ([about](https://attestedintelligence.com/about)). Described
stack: Ed25519 / ML-DSA-65, hash-linked receipt chains, Merkle checkpoint anchoring, a policy
enforcement gate, two-process key separation. That emphasis on enforcing policy at runtime,
rather than only recording, differs materially from ours.

**Publication status: not published.** Not found in Google Patents, Justia or Patent Public
Search; Patent Center returned no public data. Under 35 U.S.C. 122(b)(1)(A), applications publish
"promptly after the expiration of a period of 18 months from the earliest filing date for which a
benefit is sought" ([text](https://www.law.cornell.edu/uscode/text/35/122)), pointing to roughly
**late June 2027**. Under 122(b)(2)(B) an applicant certifying no foreign filing may request
non-publication, keeping the text secret until grant.

**Consequence, stated plainly: nobody outside that company can currently know what it claims.**
Not us, not our attorney. The number says nothing about scope, claims typically narrow during
prosecution, and any assessment of overlap is impossible today.

**Inference (verify with counsel):** the "19" series code indicates a non-provisional utility
application; provisionals use the 63 series
([USPTO](https://www.uspto.gov/patents/apply/filing-online/info-application-number)). It could
still claim priority to an earlier unpublished provisional.

---

## 4. Our position (facts only)

Development began ~March 2026; standard and reference implementations public on GitHub, npm and
PyPI since ~April-May 2026; `INTEGRITY_SPEC_V1.md` dated 2026-04-09.

- **Against later filings by others:** a public enabling disclosure is prior art under
  35 U.S.C. 102(a)(1) ([text](https://www.law.cornell.edu/uscode/text/35/102)), so our 2026
  publications count against applications with effective filing dates after ours. They are
  **not** prior art against a December 2025 filing.
- **Against ourselves:** 102(b)(1) excepts "a disclosure made 1 year or less before the effective
  filing date of a claimed invention" where it came from the inventor. **Inference:** our US
  filing deadline is roughly **April-May 2027**, keyed to our *earliest* enabling disclosure.
  Counsel must fix that date; git history and npm/PyPI publish timestamps are the evidence.
- **Outside the US:** the EPO and most jurisdictions apply absolute novelty with no equivalent
  grace period (EPC Art. 54, [EPO](https://www.epo.org/en/legal/epc/2020/a54.html)), so our
  publications plausibly affect foreign options already.

**Defensive publication.** An enabling public description permanently enters the 102(a)(1)
prior-art pool and can block later third-party claims, at no prosecution cost and with no
exclusionary right for us. Statutory Invention Registration was repealed by the AIA, leaving
ordinary publication, IP.com / Research Disclosure, or what we already did: a dated, versioned,
publicly archived spec with test vectors.

**What CC0 does.** It waives copyright, not patent rights. Its effect here is evidentiary: a
dated, public, enabling spec is prior art. Separately, Apache-2.0 on the reference
implementations carries an express patent grant binding us as contributors.

**Cost.** [BitLaw](https://www.bitlaw.com/guidance/patent/what-does-a-patent-application-cost.html)
puts drafting a software non-provisional at **$13,000-$16,000** ($17,000+ if complex),
small-entity filing fee ~$800, office-action responses $3,500-$4,500 each, and
**$15,000-$25,000 total before issuance**; a provisional is ~$3,000 of attorney work and does
not reduce total cost. A provisional buys 12 months under 35 U.S.C. 119(e). For pendency use the
USPTO [dashboard](https://www.uspto.gov/dashboard/patents/).

---

## 5. Ten questions for the attorney, in decision-changing order

1. Given section 2, especially RFC 6962/9162, SCITT, Rekor and C2PA, is there any claim you could
   get allowed over eligibility and over novelty/obviousness? Sketch it before we spend money.
2. **File at all, or defensively publish?** If the realistic outcome is a narrow claim of low
   enforcement value, what does filing buy a company our size beyond signalling?
3. **What is our real 102(b)(1) deadline?** Pin it to our earliest enabling disclosure. What
   evidence do you need?
4. Have our 2026 publications already foreclosed the EPO and other absolute-novelty
   jurisdictions, and does that change the value of a US-only filing?
5. **Freedom to operate:** how do we approach FTO when 19/433,835 is unpublished and unknowable
   until mid-2027 at the earliest? What monitoring, and what would we do differently meanwhile?
6. Cheapest credible defensive posture: provisional now, defensive publication, or both, in what
   order?
7. Does the Apache-2.0 patent grant, or the CC0 spec, limit what we could later assert, and does
   it change how we should draft?
8. Which of the four mechanisms in section 1 is most likely genuinely novel, and what searching
   would you run to check?
9. If a competitor patent later issues here, what defensive tools exist (prior commercial user
   rights under 35 U.S.C. 273, IPR, preissuance submissions under 122(e) once it publishes), and
   how do we preserve them now?
10. What should we say publicly about patents, and stop saying?
