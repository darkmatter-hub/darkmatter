# DarkMatter — Pre-Launch Security Review

**Date:** 2026-08-19
**Scope:** `src/server.js`, `src/{integrity,append-log,merkle,keys,witness,checkpoint,attestation,billing}.js`, `supabase/schema_full.sql`
**Method:** static read of the code paths. No server was run, no `.env` was read, no network calls to production. Three findings were confirmed by executing the exact hashing / Merkle code offline against synthetic inputs.

> **Citation note.** `src/server.js` was being edited by another process during this review and shifted by ~27 lines mid-pass. All line numbers below were re-derived in one atomic pass against:
> - `src/server.js` — md5 `60dc4cc134aea2075410727aa6c6ede2`, 8043 lines
> - `supabase/schema_full.sql` — md5 `62f949a218079788cac57e9577d1bc50`
>
> If the file has moved again, the quoted code fragments are the durable anchor.

---

## Executive summary

The perimeter is genuinely well built — Stripe webhook verification, injection surface, XSS escaping, Merkle tree math, key lifecycle, and admin gating are all clean — but the authorization layer and the integrity layer each have defects that are fatal for this specific product. Confirmed: **3 Critical, 10 High, 15 Medium, 9 Low**. Authorization fails systemically rather than incidentally: RLS is bypassed on every route because everything uses the service-role client, and roughly two dozen routes take a `:ctxId`/`:traceId` straight from the request into a service-role query with no ownership check, so any customer with any API key can read or graft onto any other customer's records. The integrity failure is worse in kind: `payload_hash` is computed with `JSON.stringify(payload, Object.keys(payload).sort())`, which is a *key allowlist*, not a sorter — it silently empties every nested object before hashing, so two commits with entirely different nested payloads hash identically.

**The single most important thing to fix is F2 (payload hash does not cover the payload).** Every other finding is a breach; this one means the product's central claim has never been true, including for records already written.

---

# CONFIRMED FINDINGS

## CRITICAL

### F1 — Unauthenticated takeover of any existing account's data plane
**`src/server.js:662` (`POST /api/provision`), exploit at `:685-700`**

`/api/provision` is unauthenticated by design (frictionless onboarding). When `createUser` fails because the email already exists, the handler does not stop — it looks the existing user up and creates a **new agent under that user's `user_id`**, then returns the fresh API key in the HTTP response:

```js
if (authError.message?.includes('already been registered') || authError.code === 'email_exists') {
  const { data: existingUsers } = await supabaseService.auth.admin.listUsers();   // :691
  const existing = existingUsers?.users?.find(u => u.email === email.toLowerCase());
  if (!existing) return res.status(409).json(...);
  userId = existing.id;                       // ← victim's user_id
}
// ... insert agent with user_id: userId ...
res.status(201).json({ agentId, agentName, apiKey, ... });   // ← live key handed to the caller
```

**Exploit path**
```
POST /api/provision  {"email":"victim@customer.com","agentName":"x"}
→ 201 { "apiKey": "dm_sk_..." }          # key is bound to the victim's user_id
GET  /api/search   -H "Authorization: Bearer dm_sk_..."
→ every commit across every one of the victim's agents, full payloads
```
`/api/search` (`:3768`) and `/api/threads` (`:4740`) scope by `req.agent.user_id`, so the key grants read access to the victim's entire corpus plus write access to their ledger under an agent they never created.

Rate limit is 10/hour/IP — ample. Practical limiter: `listUsers()` with no arguments returns page 1 only (GoTrue default 50 users), so today the attack lands on the 50 oldest accounts. That is a coincidence of a pagination bug, not a control.

**Fix.** Delete the "user already exists" branch — return 409 unconditionally. A caller who cannot authenticate must never be handed credentials for an account that already exists.

---

### F2 — `payload_hash` does not cover the payload; tamper-evidence does not hold
**`src/server.js:1760-1776`**

```js
const normalizedPayload   = JSON.stringify(resolvedPayload, Object.keys(resolvedPayload).sort()); // :1760
const serverPayloadHash   = crypto.createHash('sha256').update(normalizedPayload).digest('hex');
const serverChainInput    = serverPayloadHash + (parentHash || 'root');                            // :1774
const serverIntegrityHash = crypto.createHash('sha256').update(serverChainInput).digest('hex');
```

The second argument to `JSON.stringify` is a **replacer**. When it is an array it acts as a property *allowlist* applied recursively at every nesting depth — it does not sort. Since the allowlist is built from the *top-level* keys only, every nested object serializes as `{}`.

Verified by running the exact expression:
```
A = { input:'do the thing', output:'ok', memory:{ tool:'transfer', amount:10,      to:'alice'    } }
B = { input:'do the thing', output:'ok', memory:{ tool:'transfer', amount:1000000, to:'attacker' } }

serialize(A) = serialize(B) = {"input":"do the thing","memory":{},"output":"ok"}
sha256        = 86850cf8fc2bebbeef14502fffa70315b441457b95838de151ba17cd3492d8a5   (identical)
```
Arrays of objects collapse too: `artifacts:[{name:'a',sha:'deadbeef'}]` serializes as `[{}]`.

Because `integrity_hash = sha256(payload_hash ‖ parent_hash)`, the integrity hash inherits the defect and additionally binds neither agent identity nor timestamp — two different agents committing at different times produce the same `integrity_hash`.

**Exploit path.** Anyone with database write access (an insider, a leaked service-role key, a future injection) can rewrite `commits.payload.memory`, `commits.payload.artifacts`, or any nested field of any historical commit, and every verification surface — `/r/:traceId`, `/api/verify`, `/api/export`, `/api/bundle`, the published `verify_darkmatter_chain.py` — will still report `chain_intact: true`. No external party can detect the alteration. For a product whose entire value is "a third party can verify what the agent did", this is the failure mode that matters.

**Fix.** Use `hashPayload()` from `src/integrity.js:90` — it already implements correct recursive canonicalization and is currently dead code. Replace the chain input with the envelope construction at `src/integrity.js:149` (`computeIntegrityHash(payloadHash, parentHash, agentId, keyId, timestamp)`) so identity and time are bound. Then backfill correct hashes into new columns and publish an honest advisory that pre-migration chain hashes did not cover nested payload content — the alternative is silently rewriting history in a tamper-evidence product.

---

### F3 — Cross-tenant exfiltration: `POST /api/share/:ctxId` computes the ownership check and discards it
**`src/server.js:3896`, defect at `:3901-3908`**

```js
// Verify the context belongs to this user's agents          ← :3901, comment only
const { data: userAgents } = await supabaseService
  .from('agents').select('agent_id').eq('user_id', req.agent.user_id);
const agentIds = (userAgents || []).map(a => a.agent_id);     // ← :3904, never used again

const { data: commit } = await supabaseService
  .from('commits').select('id, from_agent, to_agent').eq('id', ctxId).single();
if (!commit) return res.status(404).json({ error: 'Context not found' });
// ... inserts the share link ...
```

`agentIds` is computed and then never referenced. Any commit id is shareable by any API key holder.

**Exploit path**
```
POST /api/share/<victim ctx id>  -H "Authorization: Bearer <attacker dm_sk_...>"
→ { "shareId": "share_<16 hex>" }
GET  /api/chain/share_<...>       (no auth at all — src/server.js:4015)
→ up to 50 commits of the victim's chain, each with the full `payload` object
```

A clean two-request exfiltration primitive requiring only a free account and one commit id. Commit ids leak from `/r/` pages, share links, exported bundles, and the enumeration paths in F13.

**Fix.** Restore the check the comment promises: `if (!agentIds.includes(commit.from_agent) && !agentIds.includes(commit.to_agent)) return res.status(404)`.

---

## HIGH

### F4 — Systemic missing ownership checks on id-taking routes (IDOR class)
Every route below takes an id from the request and queries with `supabaseService` (service role, RLS bypassed) with **no ownership predicate**. Authentication is checked; authorization is not.

| Route | Line | Auth | What leaks |
|---|---|---|---|
| `GET /api/replay/:ctxId` | 2197 | any API key | `select('*')`, **full payloads** of up to 50 commits |
| `GET /api/export/:ctxId` | 2486 | `flexAuth` | `select('*')`, up to 200 commits + proofs |
| `GET /api/bundle/:ctxId` | 4253 | any API key | `select('*')`, 50 commits |
| `GET /api/diff/:ctxIdA/:ctxIdB` | 3824 | any API key | full payloads of **two** arbitrary chains |
| `GET /api/content/:ctxId` | 4702 | any API key | `commit_content` + `commit_attachments` — full conversation text |
| `GET /api/lineage/:ctxId` | 2141 | any API key | chain metadata, agent ids, hashes |
| `GET /api/retention/:ctxId` | 4093 | any API key | timestamps, agent id, plan tier |
| `GET /api/share/:ctxId/markdown` | 3940 | any API key | chain length, model names, agent names |
| `GET /api/commits/:commitId/signature` | 2940 | any API key | `select('*')` into signature verification |
| `GET /api/workspace/download/:traceId` | 6970 | any session | full commit rows for any id or trace_id |
| `GET /enterprise/report/:traceId` | 3658 | API key + F6 | `select('*')` for an entire trace |

**Exploit path.** `GET /api/replay/<any ctx id>` with a free-tier API key returns another tenant's decision payloads verbatim.

**Fix.** One shared helper applied at the top of each handler:
```js
async function assertOwnsChain(userId, ctxId) {
  const { data: c } = await supabaseService.from('commits')
    .select('from_agent, to_agent, agent_id').eq('id', ctxId).single();
  if (!c) throw new NotFound();
  const { data: mine } = await supabaseService.from('agents')
    .select('agent_id').eq('user_id', userId);
  const ids = new Set((mine || []).map(a => a.agent_id));
  if (!ids.has(c.from_agent) && !ids.has(c.to_agent) && !ids.has(c.agent_id)) throw new NotFound();
}
```
Return 404, not 403, so the routes stop confirming which ids exist. `/api/workspace/conversation/:traceId` (`:7904`) is the one route in the file that already does this — use it as the template after fixing F7.

---

### F5 — Cross-tenant *write*: fabricated steps can be injected into another customer's public record
**`src/server.js:1691` (`toAgentId`, `parentId`, `traceId`), `src/server.js:2292` (`/api/fork/:ctxId`)**

`/api/commit` validates that the recipient agent *exists* (`:1912-1917`) but never that it belongs to the caller. `parentId` and `traceId` are accepted verbatim with no check at all. The row is stored with `verified: true, verification_reason: 'API key authenticated'` (`:1974-1975`).

`/r/:traceId` (`:4846`) collects commits by `.eq('trace_id', traceId)`, walks `parent_id` upward **and** `.in('parent_id', ...)` downward, and renders everything it finds as steps of that record.

**Exploit paths**
1. **Poison a public proof record.** `POST /api/commit {"traceId":"<victim trace>","payload":{...fabricated...}}` → the fabricated step renders on the victim's public `/r/<trace>` page, badged verified, indistinguishable from real steps. For a product sold as court-grade evidence this is the worst possible write primitive.
2. **Graft onto a victim's chain.** `POST /api/fork/<victim ctx id>` (`:2292`) — the fork point is fetched with no ownership check, `toAgentId` is only checked for existence, and the row is inserted with `verified: true`. The forked child appears in the victim's `/r/` forward walk.
3. **Inject into a victim's inbox.** `/api/pull` (`:2118`) returns `.eq('to_agent', agent_id).eq('verified', true)` — a commit addressed to another tenant's agent lands in their feed as verified input.
4. **Hijack a thread.** `/api/commit/rich` (`:4548`) sets `threadId = traceId` (`:4659`) and updates `conversation_threads` with `.eq('id', threadId)` and no `user_id` scope, bumping another tenant's thread pointer and turn count.

**Fix.** Reject `toAgentId`, `parentId`, and `fromCheckpoint` unless the referenced agent/commit belongs to the caller's `user_id`. Namespace `trace_id` per user (store `user_id` on the commit; require uniqueness within a user) and have `/r/` select only commits belonging to the trace owner. Scope the `conversation_threads` update by `user_id`.

---

### F6 — Any user self-grants an Enterprise entitlement
**`src/server.js:3033` (`POST /enterprise/register`), `src/server.js:2972` (`requireEnterprise`), `supabase/schema_full.sql:405`**

`POST /enterprise/register` is gated on `requireAuth` only — no subscription check, no plan check, no admin check. It inserts into `enterprise_accounts`, where `active boolean DEFAULT true`. `requireEnterprise` only asks for a row with `active = true`.

**Exploit path**
```
POST /auth/signup                                    # free account
POST /enterprise/register {"companyName":"x"}        # now "Enterprise"
POST /dashboard/agents                               # get an API key
GET  /enterprise/report/<any traceId>                # select('*') for that whole trace
```
Bypasses billing and chains into the F4 read primitive.

**Fix.** Gate `/enterprise/register` on an active `subscriptions.plan = 'enterprise'` row and insert with `active: false` pending manual activation. Add an ownership check to `/enterprise/report/:traceId`.

---

### F7 — Workspace-admin check is workspace-agnostic, defeating the one good authz check in the file
**`src/server.js:7934`** (in `/api/workspace/conversation/:traceId`, `:7904`)

```js
const membership = await getMembership(req.user.id);
const isAdmin    = membership?.role === 'admin';       // :7934
if (!hasAccess && !isAdmin) return res.status(403).json({ error: 'Access denied' });
```

`isAdmin` means "is an admin of *some* workspace", never "is an admin of the workspace that owns this conversation". `POST /api/workspace` (`:5918`) makes the creator an `admin` member of their own new workspace immediately (`:5943`).

**Exploit path.** `POST /api/workspace {"name":"x"}` → you are now `role: 'admin'` → `GET /api/workspace/conversation/<any traceId>` returns the full transcript (`select('*')`) of any tenant's conversation.

**Fix.** Resolve the workspace that owns the commits (via `workspace_members.agent_id`) and require `membership.workspace_id` to equal it.

---

### F8 — Live API keys stored in plaintext alongside their hashes
**`supabase/schema_full.sql:153` (`api_key text NOT NULL`); written at `src/server.js:712, 1286, 1337`; read at `src/server.js:462-503`**

The `api_key_hash` migration was never completed. Every creation path still writes the plaintext key, and `requireApiKey` still falls back to `.eq('api_key', apiKey)`. A database read — backup, replica, leaked service-role key, a future injection — yields every customer's live agent credentials directly. `maskApiKey(a.api_key)` at `:1392` also requires selecting the plaintext column just to render a display hint.

**Fix.** Drop the plaintext fallback in `requireApiKey`, add a `key_hint` column populated at creation, stop selecting `api_key`, then `ALTER TABLE agents DROP COLUMN api_key`. `proxy_keys.proxy_key` (`schema_full.sql:626`, matched at `:5499` and `:6321`) has the same plaintext-storage problem and needs the same treatment; the masking at `:6287` protects the API response but not the database.

---

### F9 — Customer LLM provider API keys stored in plaintext
**`src/server.js:7660` and `src/server.js:7696`**

```js
encrypted_key:     apiKey,  // TODO: encrypt with server-side key in production   ← :7660
```

`POST /api/workspace/provider-keys` (`:7617`) writes raw `sk-ant-...` / `sk-...` keys into `workspace_provider_keys.encrypted_key` and, on the fallback path (`:7696`), into `user_recording_keys.encrypted_key` — the *same column* that `POST /api/recording-keys` correctly AES-256-GCM encrypts via `encryptValue()` (`:42`). The column now holds a mixture of ciphertext and plaintext, and `decryptValue()` (`:59`) returns anything not shaped `iv:tag:data` unchanged, so the mixture is invisible at runtime.

**Fix.** Wrap both writes in `encryptValue()`, then migrate every row whose value does not match `/^[0-9a-f]{24}:[0-9a-f]{32}:/`. These are third-party credentials with direct billing impact — treat the exposure window as a disclosure obligation.

---

### F10 — Rich-commit content is entirely outside the hash chain
**`src/server.js:4565-4600`**

`/api/commit/rich` hashes only a derived summary object:
```js
const summary = textContent.slice(0, 500) + (textContent.length > 500 ? '...' : '');   // :4565
const payload = { summary, charCount, hasImages, hasCode, format, platform, model };
const payloadHash = 'sha256:' + crypto.createHash('sha256')...                          // :4586
```
The actual content — `commit_content.text_content`, `commit_content.html_content`, and every row in `commit_attachments` — is written to separate tables and **covered by no hash at all**. The response returns `verified: true`.

**Exploit path.** Rewrite `commit_content.text_content` for any rich commit. `charCount` and the 500-char prefix are the only constraints, and nothing recomputes even those. `/api/content/:ctxId` will serve the altered text and `/r/` will still report the chain intact.

**Fix.** Include `sha256(canonical({text_content, html_content, attachment_hashes}))` in the hashed payload and verify it on read in `/api/content/:ctxId`.

---

### F11 — L3 client attestations are verified once and then thrown away
**`src/server.js:1793-1811` (verify) vs `src/server.js:1956-1981` (insert)**

The commit is verified against the client's Ed25519 signature at write time and `assurance_level` is set to `'L3'`. The successful insert then omits `agent_signature`, `agent_public_key`, `client_timestamp`, `accepted_at`, `key_id`, and `agent_id`. Only the opaque `client_attestation` jsonb survives. (The rejected-recipient branch at `:1930-1945` *does* store them — the success path does not.)

Consequences, confirmed against `src/keys.js:315-340`:
- `verifyCommitSignature()` reads `commit.agent_signature` → returns `{ result: 'no_signature' }` for **every** commit created through `/api/commit`. `GET /api/commits/:commitId/signature` (`:2940`) can therefore never succeed.
- The signed envelope binds `client_timestamp`, which is never persisted, so the envelope cannot be reconstructed even if the signature were stored.
- `commits.accepted_at` — documented in the schema as "Set by server, not alterable by client" — is `NULL` on every successful commit. `/api/workspace/members` (`:5991`) filters on `.gte('accepted_at', ...)` and so always returns zero week-commits.
- The export bundle advertises an `agent_signatures` verification phase (`:2611`) that no bundle can pass.

The L3 badge shown on `/r/` is an assertion by the server that no third party can check — precisely the property L3 exists to avoid.

**Fix.** Add `agent_signature`, `agent_public_key`, `key_id`, `client_timestamp`, `accepted_at`, and `agent_id` to the insert at `:1956`.

---

### F12 — Server checkpoint signing key silently falls back to an ephemeral key
**`src/append-log.js:50-61`**

```js
} catch (err) {
  console.error('[append-log] ✗ Failed to load key:', err.message);
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  _serverKey = privateKey;
  console.warn('[append-log] WARNING: Using ephemeral fallback key');   // :55
}
```
Also at `:60` when `DM_LOG_SIGNING_KEY_PEM` is unset. The only signal is a console warning; the process starts and serves normally.

**Impact.** Every checkpoint signed before the restart fails verification against the key now served by `getServerPublicKeyPem()`. Checkpoints already published to the GitHub checkpoint repo become permanently unverifiable. A verifier cannot distinguish this from active forgery — converting an operational slip into an apparent integrity breach.

**Fix.** `process.exit(1)` when the key is missing or unloadable and `NODE_ENV === 'production'`. Expose the key fingerprint on a health endpoint so rotation is detectable.

---

### F13 — Every commit is world-readable; no visibility model exists
**`src/server.js:4846` (`GET /r/:traceId`), `src/server.js:5300` (`GET /verify/:commitId`)**

Neither route requires authentication, and the `commits` table has no public/private/shared column (`schema_full.sql:286-347`). `/r/` resolves by `id` **or** `trace_id`, walks parents up and children down, and renders `payload.input`, `.output`, `.text`, `.prompt`, `.summary`, `.convTitle`.

`trace_id` is a free-form string supplied by the customer at `/api/commit`. Any customer using a readable trace id — `"run-1"`, `"session-2026-08-19"`, `"order-84721"` — has published that record to the open internet. `?format=json` returns it as a downloadable bundle.

Commit ids are `ctx_<Date.now()>_<12 hex>` from `/api/commit` and `ctx_<Date.now()>_<8 hex>` from `/api/commit/rich`; the latter is 32 bits of entropy plus a millisecond that is often narrowly bounded.

**Fix.** Add `visibility` to `commits`, default `'private'`. Serve `/r/` and `/verify/` only for explicitly published records, or behind an unguessable token — which `/chain/:shareId` already does correctly with 64 bits.

---

## MEDIUM

### F14 — Unauthenticated attacker can permanently block legitimate witness signatures
**`src/server.js:2730` (`POST /api/witness/sign`), `src/witness.js:221-231`, `supabase/schema_full.sql:1230`**

The endpoint has no auth and no rate limiter. The signature *is* correctly verified, but the row is inserted regardless, with `sig_valid: false`. `witness_sigs` has `UNIQUE (checkpoint_id, witness_id)`, and the insert error handler swallows anything containing "duplicate":

```js
if (insertErr && !insertErr.message.includes('duplicate')) throw new Error(...)   // witness.js:229
```

**Exploit path.** Poll `/api/witnesses` (public, `:2697`) for witness ids and watch for new checkpoint ids. `POST /api/witness/sign` with `{checkpoint_id, witness_sig: "00"}` and `X-Witness-ID: <real witness>` before the real witness responds. The junk row wins the unique constraint; the genuine signature is later silently discarded as a duplicate. The checkpoint never reaches `witness_status: 'witnessed'`.

An attacker can hold every future checkpoint in this state indefinitely — defeating the "independence beyond operator" property the witness system exists to provide.

**Fix.** Require a witness-authenticated call (mutual TLS or a per-witness bearer token). Reject invalid signatures with 400 instead of storing them. Make a valid signature replace an invalid one.

### F15 — The public verification page claims verification it does not perform
**`src/server.js:4919` (the check), `src/server.js:5253` (the claim)**

The only check performed is `commits[i].parent_hash !== commits[i-1].integrity_hash`, skipped entirely when either value is null, over a list sorted by **timestamp** rather than by actual parent linkage. The rendered proof card says: *"N steps — payload hash, integrity hash, parent link, assurance level verified per commit."*

`payload_hash` is never recomputed from `payload`. `integrity_hash` is never recomputed from its inputs. `assurance_level` is displayed, not verified. This is why F2 and F10 went unnoticed. The same shallow check appears in `/api/verify/:ctxId` (`:2429`), `/api/chain/:shareId` (`:4015`), `/api/bundle/:ctxId` (`:4253`), and `/enterprise/report/:traceId` (`:3658`).

**Fix.** After F2 lands, actually recompute both hashes per commit and order by parent linkage, not timestamp. Until then, change the copy to describe only the parent-link check.

### F16 — Four incompatible integrity-hash constructions; the specified one is dead code
| Path | Payload hash | Chain hash |
|---|---|---|
| `/api/commit` `:1760` | `sha256(JSON.stringify(p, sortedTopKeys))` | `sha256(ph + (parent‖'root'))` |
| `/api/commit/rich` `:4586` | `'sha256:'+sha256(JSON.stringify(p))` | `'sha256:'+sha256(ph + (parent‖'') + ctxId)` `:4596` |
| proxy / workspace-chat | `sha256(JSON.stringify(p))` | `sha256(ph + parent)` |
| `src/integrity.js:90,149` — **the published spec** | canonical envelope | `sha256(canonical(envelope))` |

`src/server.js:10` imports `hashChain` and `verifySignature` from `integrity.js`; neither is exported (`integrity.js:281`), so both are `undefined`. Nothing in `integrity.js` is called from `server.js`. `src/attestation.js` — the ENVELOPE_SPEC_V1 reference implementation with its own frozen test vectors — is never imported by anything.

**Impact.** `INTEGRITY_SPEC_V1.md` and `ENVELOPE_SPEC_V1.md` are served to customers (`:352`, `:356`) and describe a construction the server does not use. No third party can recompute any stored hash from the published spec.

**Fix.** Make `integrity.js` the single write path for all four commit routes; delete the ad-hoc constructions.

### F17 — Proof-receipt URLs return 404
**`src/server.js:2094-2096`, `:2608`**

Every commit receipt and export bundle embeds `pubkey_url: /api/log/pubkey`, `checkpoint_url: /api/log/checkpoint`, and `verify_url: /api/log/proof/<commitId>`. Only `/api/log/checkpoint/:checkpointId/witnesses` (`:2754`) is registered. The offline verifier advertised at `:2608` needs the server public key from a dead URL. The transparency-log proof is not independently obtainable.

**Fix.** Register the three routes — `getServerPublicKeyPem()` and `generateProofForCommit()` already exist in `append-log.js` and are exported.

### F18 — Workspace invitations are not bound to the invited email; join codes are 32-bit and unrate-limited
**`src/server.js:6107` (`POST /api/workspace/join`), `supabase/schema_full.sql:937`**

The token path fetches the invitation and joins `req.user.id` without ever comparing `req.user.email` to `invitation.email` — a forwarded invite link is a working credential for any account. The `joinCode` path grants membership with no invitation at all; `join_code` defaults to `upper(substring(uuid,1,8))` = 32 bits, and the route carries no rate limiter (`wsAuth` only). Against N workspaces the expected work to hit *some* workspace is 2³²/N requests. Membership then yields `/api/workspace/members` (`:5991`), which returns `select('*')` (`:5998`) — every member's email, display name, role, and agent id — to any member, admin or not.

**Fix.** Require `invitation.email === req.user.email`. Increase `join_code` to ≥128 bits or remove the join-code path. Apply `authLimiter` to `/api/workspace/join`. Restrict the member roster to non-PII fields for non-admins.

### F19 — `POST /auth/reset-password` accepts any access token and enforces no password policy
**`src/server.js:1019`, defect at `:1025`**

```js
const { data: { user }, error: sessionError } = await supabaseService.auth.getUser(token);   // :1025
if (sessionError || !user) return res.status(400).json({ error: 'Invalid or expired reset link' });
await supabaseService.auth.admin.updateUserById(user.id, { password });
```

`getUser()` validates *any* Supabase access token, not specifically a recovery token. There is no current-password check and no length check (signup requires 8 at `:837`; this route requires none).

**Impact.** Any exposure of a short-lived access token — an XSS, a logged `Authorization` header, a proxy log — escalates to permanent account takeover, because the attacker sets the password without re-authenticating. It also permits one-character passwords.

**Fix.** Require the current password, or verify the token carries a recovery AMR claim. Apply the same ≥8-character policy as signup.

### F20 — `err.message` returned to clients in ~100 handlers
Confirmed at 105 sites across `src/server.js` and `src/billing.js`. The auth routes were **not** in fact fixed — `:850, 896, 915, 918, 977, 992, 1030, 1034` still return Supabase error text verbatim. `:5445`-region (`claudeProxyAuth`) and `:6337`-region (`proxyAuth`) prepend a label to the raw message from the auth middleware itself.

Supabase error strings routinely carry table names, column names, constraint names, and RLS policy names. Combined with the `.single()` calls throughout, a probing attacker gets a free schema map.

**Fix.** One error middleware: log `err` server-side with a correlation id, return `{ error: 'Internal error', ref: <id> }`. Keep specific messages only for deliberate 4xx validation responses.

### F21 — JWT verification does not validate audience, issuer, or role
**`src/server.js:511-522` (`_verifyJwt`), `:523` (`_claimsToUser`)**

`_verifyJwt` checks the HS256 signature and `exp` only. It never checks `aud`, `iss`, or `role`, and `_claimsToUser` maps `sub`/`email`/`role` straight onto `req.user`. Supabase signs the project's **anon key** and **service_role key** with this same secret. The anon key is a semantically public value with a multi-year `exp`; presenting it to `requireAuth` (`:529`) / `wsAuth` (`:5867`) / `flexAuth` (`:583`) passes signature verification and yields `req.user = { id: undefined, email: undefined, role: 'anon' }`.

Practical impact today is limited — downstream queries with `user_id = undefined` fail rather than returning data, `isAdminEmail(undefined)` is false, and the anon key is not shipped to browsers in this app (the front end uses httpOnly cookies). This is a latent bypass rather than an active one, but it is the wrong shape of check to leave in an auth path.

The comparison `expected !== sig` (`:517`) is also not constant-time; low practical risk against HMAC-SHA256 over a network, but `crypto.timingSafeEqual` is free.

**Fix.** Require `claims.aud === 'authenticated'` and `claims.role === 'authenticated'`, verify `iss`, reject when `sub` is absent, and use `timingSafeEqual`.

### F22 — `/auth/session` pairs a validated access token with an unvalidated refresh token
**`src/server.js:968`, callback at `:928`**

The access token is validated; the refresh token is written to a cookie with no check that it belongs to the same user. `/auth/callback` posts fragment tokens here with no `state` parameter and no CSRF token, so an attacker can drive a victim's browser to `/auth/callback#access_token=<attacker's>&refresh_token=<attacker's>` and fix the victim's session to the attacker's account — a login-CSRF that causes the victim's subsequent work to be recorded in the attacker's ledger. When `requireAuth` later refreshes on expiry, it trusts whatever refresh token is in the cookie.

**Fix.** Verify that the refresh token resolves to the same `sub` as the access token before setting cookies. Carry a `state` nonce through the OAuth/confirmation round trip.

### F23 — `deliverWebhook` is called but never defined
**`src/server.js:2007`**

`grep` finds exactly one occurrence in the file. The call is `deliverWebhook(...).catch(...)`; the synchronous `ReferenceError` is not caught by `.catch()` and propagates to the handler's outer `try`, producing a 500 — **after** the commit has already been inserted and appended to the log.

**Impact.** Any agent with `webhook_url` set makes every commit addressed to it return HTTP 500 while the commit is durably stored. SDK clients retry, producing duplicate ledger entries. In an append-only evidence system, silently double-recording on a false failure signal is a data-integrity problem, not just a bug.

**Fix.** Implement or remove it; move all post-insert side effects after the response is sent, inside their own try/catch.

### F24 — `/api/provision` emails a live API key in cleartext to an arbitrary address
**`src/server.js:662`, email body at `:726-746`**

Unauthenticated, 10/hour/IP. Sends `API key: dm_sk_...` in a plain-text email from `hello@darkmatterhub.ai` to any address the caller names. This is both credential-over-email and a spam/phishing primitive using the product's own authenticated sending domain.

**Fix.** Email the magic link only; require the user to retrieve the key from the dashboard.

### F25 — Account deletion is likely to fail or half-complete
**`src/server.js:1053` (`POST /api/account/delete`), commit-deletion loop at `:1105`; `supabase/schema_full.sql:1884, 1812`**

`log_entries_commit_id_fkey` references `commits(id)` with **no** `ON DELETE CASCADE` (`schema_full.sql:1884`), and `commits_from_agent_fkey` references `agents(agent_id)` likewise (`:1812`). Step 3 deletes commits inside a `try` that logs and continues, so any commit with a log entry — i.e. every successfully logged commit — blocks deletion silently; step 4's `agents` delete then blocks on the surviving commits.

Partially suspected: whether the run ends in a 500 at step 5 or in a success response over undeleted data depends on how the auth-user cascade resolves at runtime, which I could not determine statically. Either outcome breaks the deletion promise in the privacy policy.

**Fix.** Add `ON DELETE CASCADE` to `log_entries_commit_id_fkey`, or anonymise rather than delete (the append-only guarantee argues for anonymisation anyway). Do not return `{deleted: true}` unless every step succeeded.

### F26 — `/api/debug/me` is documented admin-only but has no admin check
**`src/server.js:7178`** — the comment says "(admin only)", the gate is `requireAuth`. Returns `null_user_id_agents` — up to 5 orphaned agent ids belonging to other accounts — plus a verbose diagnosis string. **Fix.** Add `isAdminEmail(req.user.email)` or delete the route.

### F27 — SSRF allowlist is name-based only
**`src/server.js:403` (definition), `:4151` (call from `POST /api/hooks`, `:4137`)**

`isValidWebhookUrl` blocks a literal hostname list and three IPv4 CIDR regexes against the *hostname string*. It does not resolve DNS, so `127.0.0.1.nip.io`, a DNS-rebinding host, or any attacker-controlled name resolving to `169.254.169.254` all pass. It also misses decimal (`2130706433`), octal (`0177.0.0.1`), short-form (`127.1`), `[::]`, and IPv4-mapped IPv6. Reachable by any API key holder.

**Fix.** Resolve the hostname and check every resulting address against private/link-local/loopback ranges, re-check on redirect, and pin the resolved address for the request.

### F28 — Billing identity is resolved by email, and `listUsers()` is unpaginated in the webhook
**`src/server.js:7034, 7060` (webhook), `:3494, 3555, 3597` (subscription / checkout / portal)**

The Stripe webhook resolves `user_id` by scanning `listUsers()` for a matching email — page 1 only, 50 users. Beyond the 50th account, paid subscriptions are silently never applied. `/api/billing/portal` (`:3588`) issues a Stripe billing-portal session for whichever customer matches `req.user.email` (`:3597`), granting access to invoices, payment-method metadata, and subscription cancellation.

**Fix.** Resolve strictly by `customer.metadata.user_id` (already set at checkout, `:3579`); never fall back to email. Paginate `listUsers()` in the webhook or replace it with a `subscriptions`-table lookup.

---

## LOW

- **F29** `src/server.js:3794` — `query.or(\`from_agent.eq.${agentId},...\`)` interpolates `req.query.agentId` unescaped into a PostgREST filter. `searchParams.append` percent-encodes, and the tenant filter at `:3785` is a separate `or=` param that PostgREST ANDs, so scope cannot be widened — but it is the only user-controlled filter interpolation in the file. Validate against `/^dm_[0-9a-f]{16}$/`.
- **F30** `src/append-log.js:38, 44` — logs `rawPem.slice(0, 30)` and `keyMaterial.slice(0, 40)` of the signing key file at startup. Only ASN.1/PEM header bytes in practice, but private-key fragments should never reach stdout. `src/server.js:36-38` logs the `DM_ENCRYPTION_KEY` length.
- **F31** `src/server.js:42-51` — `encryptValue` silently stores `'plain:' + plaintext` when `DM_ENCRYPTION_KEY` is unset. Fail closed in production.
- **F32** `src/server.js:1580-1588` — `fireEventHooks` filters on `event_type` (`:1587`) and `is_active`; `event_hooks` has `events text[]` and `enabled` (`schema_full.sql:451-452`). The query errors and is swallowed, so event hooks have never fired.
- **F33** `src/server.js:199` — `contentSecurityPolicy: false`. The inline-script pages could move to nonces or hashes; CSP is the main compensating control for any future XSS on `/r/`.
- **F34** `src/server.js:5998` — `/api/workspace/members` returns `select('*')` to every member regardless of role, including all member emails.
- **F35** `src/server.js:6197` — `PATCH /api/workspace/members/:memberId` (`:6189`) writes `role` with no allowlist; an admin can set arbitrary role strings including `'owner'`.
- **F36** `src/server.js:1973-1975` — commits whose client-supplied hashes fail the server cross-check are stored with `hash_mismatch: true` **and** `verified: true, verification_reason: 'API key authenticated'`. Only `/api/commit`'s own synchronous response mentions the mismatch (`:2108`); `/r/`, `/api/verify`, and `/api/export` never surface the flag.
- **F37** `src/append-log.js:145-186` — `appendToLog` reads all log entries and computes `newPosition = count` with no transaction or advisory lock. `log_entries_pkey PRIMARY KEY (position)` (`schema_full.sql:1150`) makes concurrent appends collide; the loser is caught at `src/server.js:2078` and the commit is marked `proof_unavailable`. Under concurrency, proofs are dropped silently. It is also O(n) per commit and will not scale.

---

# SUSPECTED (not fully verified)

- **S1 — Billing-portal access via email collision.** `/api/billing/portal` (`:3588`) resolves the Stripe customer by `req.user.email` (`:3597`). If the Supabase project permits sign-in before email confirmation, registering a paying customer's email would hand over their billing portal. I could not verify the project's confirmation setting without touching `.env` or the Supabase console. If confirmation is required, this is not exploitable. Worth ten minutes to confirm.
- **S2 — Merkle root divergence.** `computeRoot` (`src/merkle.js:95`) uses bottom-up odd-node promotion rather than RFC 6962's power-of-two split. I tested n = 1..40 against a reference RFC 6962 `MTH` and found **no divergence**, and inclusion proofs round-tripped for every (n, index) pair up to n = 33. I did not test beyond 40 leaves. Very likely fine; a property test to a few thousand leaves would close it.
- **S3 — Account-deletion end state** (see F25) — whether it 500s or reports false success needs a staging run.

---

# Areas reviewed and found clean

- **Stripe webhook** (`:7001`). `stripe.webhooks.constructEvent` with the raw `Buffer` (`:7007`); the JSON body parser is correctly skipped for this path only (`:364-367`); a missing or bad signature returns 400 before any state change. Replay is bounded by Stripe's five-minute tolerance, and both handlers re-fetch live state from Stripe and upsert, so replay is idempotent — an `event.id` dedupe table would be belt-and-braces, not a fix. **Webhook-driven state changes cannot be forged.** (Identity resolution *inside* the handler is F28; the signature layer itself is sound.)
- **Injection.** No raw SQL, no string-concatenated queries, no `child_process`, no `exec`/`spawn`, no `eval`, no `new Function` anywhere in `src/`. Everything goes through the Supabase client. The only user-controlled filter interpolation is F29, which cannot widen scope.
- **Merkle tree** (`src/merkle.js`). Correct RFC 6962 domain separation (`0x00` leaves, `0x01` nodes), a structured leaf envelope binding commit id to log position, and root computation I verified equals a reference `MTH` for n = 1..40. Inclusion-proof generation and verification round-trip cleanly for every index at every size tested. This is the best code in the repo.
- **Witness signature verification** (`src/witness.js:195-217`). Envelope reconstruction is careful — it correctly maps DB `position` → envelope `log_position` and strips non-spec fields — and signatures are verified against the registered Ed25519 key before `sig_valid` is set. The witness *ID* is derived deterministically from the public key, so witness identity cannot be spoofed. The weakness is the endpoint's lack of auth (F14), not the crypto.
- **Key lifecycle** (`src/keys.js`). Registration validates `asymmetricKeyType === 'ed25519'` and rejects anything else. Rotation preserves the old key for historical verification with correct `valid_from`/`valid_until` windowing. `getKeyAtTime` correctly returns the key active at a given instant rather than the current key, and distinguishes `revoked` from `revoked_post_commit`. This is the right design; F11 is that the server never stores the data needed to exercise it.
- **Admin authorization.** `isAdminEmail` (`:123`) is applied consistently and correctly at all nine admin routes (`:6640, 6765, 6857, 6899, 6915, 7097, 7106, 7142`, plus `/admin/stats`); `filter(Boolean)` correctly prevents an empty `SUPERUSER_EMAIL` from matching an empty email. Admin actions write to `admin_audit_log`. No bypass found. (`/api/debug/me` is F26 — never gated, rather than gated incorrectly.)
- **Ownership-scoped routes that are correct.** `/dashboard/agents` CRUD + rotate (`:1320, 1358, 1404, 1421`), `/api/hooks` CRUD + deliveries (`:4180, 4195, 4211, 4228`), `/api/recording-keys` CRUD, `/api/workspace/provider-keys` CRUD (`:7722, 7765, 7791`), `/api/search` (`:3768`), `/api/threads` (`:4740`), `/api/pull` (`:2118`), `/api/agents/keys` (`:2812, 2834, 2855, 2897`), `/enterprise/did/register` (`:3097`). All correctly scope by `user_id` or `agent_id`.
- **Credential entropy.** `generateApiKey` = `crypto.randomBytes(24)` — 192 bits (`:452`). `generateAgentId` = 64 bits (`:457`). `proxy_keys.proxy_key` = two UUIDv4s, 244 bits. `shared_chains.id` = `randomBytes(8)`, 64 bits. All adequate. API-key *comparison* is a DB equality on an indexed hash column, not a byte-by-byte compare, so there is no meaningful timing oracle. Revocation works: `/dashboard/agents/:agentId/rotate` (`:1421`) overwrites both `api_key_hash` and `api_key` under a `user_id` predicate, and `DELETE /dashboard/agents/:agentId` (`:1404`) is likewise scoped.
- **XSS.** `/r/:traceId` (`:4846`) and `/verify/:commitId` (`:5300`) route all payload-derived text through `escH()` (escaping `& < > "`). The `traceId` parameter is validated against `/^[a-zA-Z0-9_-]+$/` with a length cap before use (`:4849`, and the same guard at `:6936, 6973, 7907`). `buildStandaloneHtml` (`:4765`) strips `<script>`, `on*=` handlers, and `javascript:` hrefs from stored HTML. No injection point found in any server-rendered page.
- **Rate limiting.** Sensibly differentiated: `authLimiter` 20/15min, `provisionLimiter` 10/hr, `deleteLimiter` 3/hr, `keyRegLimiter` 10/hr, `feedbackLimiter` 5/hr, `apiLimiter` 120/min. Per-email login lockout (`:261-289`) correctly complements per-IP limiting against distributed brute force. Gaps are noted individually (F14, F18).
- **CORS.** Explicit origin allowlist, no wildcard, no `Access-Control-Allow-Credentials` reflection (`:290-310`).
- **Commit immutability guard.** `DELETE` on every commit resource returns 405 with a redaction-commit hint (`:2962-2965`) — correct and well documented. (It does conflict with `/api/account/delete`; see R7.)
- **RLS policies as written** (`schema_full.sql:2027-2705`). The 63 policies are individually reasonable and correctly scoped to `auth.uid()`. The problem is not the policies — it is that no server route exercises them. See R1.

---

# Recommendations not tied to a specific defect

**R1 — Stop using the service-role client as the default.** Every route in `src/server.js` uses `supabaseService`, so all 63 RLS policies are inert. They are correct, and they would have caught F3, F4, F5, and F7 for free. Create a per-request client from the user's JWT (`createClient(url, anonKey, { global: { headers: { Authorization: 'Bearer ' + token } } })`) and use it for every user-scoped read and write. Reserve `supabaseService` for genuinely privileged operations — webhook handling, log appends, checkpointing, admin routes — and name the variable so its use stands out in review. This converts the entire IDOR class from "must remember a check on every route" into "must deliberately opt out".

**R2 — Add a cross-tenant test suite before launch.** Two fixtures, tenant A and tenant B; then for every route taking an id, assert that B's credential gets 404 on A's resource. Most of F3, F4, F5, F6, and F7 would have been caught by roughly 30 lines of test per route, and the suite prevents regression as routes are added.

**R3 — Publish a verifier and make the spec executable.** `src/integrity.js` and `src/attestation.js` are both well-written reference implementations that nothing calls, while the server uses four ad-hoc constructions. Wire the spec modules into the write path, add the vectors in `test-vectors-envelope-v1.json` to CI, and make the published `verify_darkmatter_chain.py` run against a real exported bundle in CI too. For this product, the verifier passing on real output *is* the product test.

**R4 — Treat one commit path as the only commit path.** There are four (`/api/commit`, `/api/commit/rich`, `commitProxyInteraction`, `commitWorkspaceChat`), each with its own hashing, its own column subset, and its own bugs. Collapse them onto one internal `createCommit()` that owns hashing, log append, usage accounting, and column population. Three of the Critical/High findings exist only in a subset of the paths.

**R5 — Fail closed on missing crypto configuration.** `DM_LOG_SIGNING_KEY_PEM` (F12), `DM_ENCRYPTION_KEY` (F31), and `SUPABASE_JWT_SECRET` all currently degrade silently to a weaker mode. Add a startup assertion that refuses to boot in production without them.

**R6 — Rotate credentials before launch.** Given F8 and F9, assume `agents.api_key`, `proxy_keys.proxy_key`, and the plaintext rows in `workspace_provider_keys` / `user_recording_keys` are compromised. Force-rotate all DarkMatter API keys and notify affected users to rotate their upstream provider keys.

**R7 — Decide the retention-versus-immutability question explicitly.** `/api/account/delete` (`:1053`) hard-deletes commits while `DELETE /api/commit*` (`:2962`) returns 405 with "Commits cannot be deleted." Both cannot be true. Anonymise-in-place preserves the hash chain and satisfies erasure obligations; pick it deliberately and document it, because a customer auditing the chain will notice the gap.
