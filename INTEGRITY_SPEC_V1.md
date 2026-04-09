# DarkMatter Integrity Specification v1.0

**Status:** FROZEN  
**Frozen at:** 2026-04-09  
**Spec URL:** https://darkmatterhub.ai/docs#integrity-spec  
**Test vectors:** `github-template/integrity_test_vectors.json`, `github-template/merkle_test_vectors.json`

This document is the authoritative, frozen specification for DarkMatter's integrity model.
All SDKs (Python, TypeScript, any future language) must implement this spec exactly.
Any deviation from this spec is a bug, not a feature.

Changes to this spec require a new version number and a new frozen document.
Verifiers must check `spec_version` on commits and apply the correct rules.

---

## 1. Canonical Serialization v1

All hashing in DarkMatter goes through canonical serialization first.
The same algorithm must produce byte-identical output in every language.

### Rules

1. **Object keys** are sorted lexicographically by Unicode codepoint
2. **null values** in objects are **kept** and serialized as `"null"` — `null` is not the same as a missing field
3. **undefined values** in objects are **dropped** (JavaScript only — Python has no undefined)
4. **Arrays** preserve element order (not sorted)
5. **Strings** use standard JSON encoding (delegate to `json.dumps` / `JSON.stringify`)
6. **Integers** serialize as decimal digits, no decimal point, no exponent: `42`, `-1`, `0`
7. **Floats** — non-finite values (`NaN`, `Infinity`, `-Infinity`) are **rejected** with a `TypeError`
8. **Floats** — finite values: `toPrecision(17)` then strip trailing zeros, keeping at least one decimal digit
9. **Boolean**: `"true"` or `"false"`
10. **null** (standalone): `"null"`

### Test vectors

All 18 canonicalization vectors in `integrity_test_vectors.json` MUST pass in every SDK before release.
Critical vectors: C-004 (null kept), C-011 (special chars), C-013 (unicode/emoji), C-017 (multiple nulls).

### Cross-language gotchas

- Python `None` maps to JSON `null` — must be kept in dicts, not dropped
- `lstrip('sha256:')` is WRONG — use `removeprefix('sha256:')` or `startswith` check
  (lstrip strips any char in the set, so `sha256:24bc...` becomes `4bc...`)
- `bool` is a subclass of `int` in Python — check `isinstance(v, bool)` before `isinstance(v, int)`

---

## 2. Commit Envelope v2

The envelope is the canonical object that gets hashed to produce `integrity_hash`
and signed by the agent. It binds all commit-identifying metadata.

### Schema

```json
{
  "schema_version":       "2",
  "agent_id":             "<dm_...>",
  "key_id":               "<string>",
  "timestamp":            "<ISO-8601 UTC, seconds precision, no milliseconds>",
  "payload_hash":         "<64-char lowercase hex SHA-256>",
  "parent_integrity_hash": "<64-char lowercase hex SHA-256> | \"root\""
}
```

### Rules

- `schema_version` is the string `"2"` (not integer 2)
- `timestamp` is the **client-asserted** time — `accepted_at` is separate server ledger time
- `timestamp` must have milliseconds stripped: `2026-04-09T10:00:00Z` not `2026-04-09T10:00:00.123Z`
- `parent_integrity_hash` is `"root"` for root commits (not `null`, not empty string)
- All hex hashes are lowercase with no `sha256:` prefix inside the envelope

### Integrity hash computation

```
payload_hash    = SHA-256( canonical(payload) )
envelope        = { schema_version, agent_id, key_id, timestamp, payload_hash, parent_integrity_hash }
integrity_hash  = SHA-256( canonical(envelope) )
```

Two commits with identical payloads and parents but different agents, keys, or timestamps
produce **different** integrity hashes. This gives every commit a unique cryptographic identity.

---

## 3. Agent Signature

Agents sign the canonical envelope — not the payload directly.
Signing the envelope authenticates: payload content, chain position, agent identity, key identity, timestamp, schema version.

```
signature = Ed25519_sign( private_key, UTF-8( canonical(envelope) ) )
```

- Algorithm: Ed25519 only
- Message: `UTF-8(canonical(envelope))` — the same bytes used for `integrity_hash`
- Stored as: lowercase hex string in `agent_signature` field
- Private key: never stored by DarkMatter — only the public key PEM is registered

### Key lifecycle

- Keys are registered with `key_id` (default: `"default"`) and `valid_from` timestamp
- **Rotation** sets `valid_until` on the old key and registers a new key
  - Old key remains valid for historical verification of past commits
  - New commits must use the new key
- **Revocation** marks a key as revoked with a reason and timestamp
  - Commits signed after revocation are flagged `revoked_key`
  - Commits signed before revocation are flagged `revoked_post_commit` (integrity unaffected)
- Historical verification: use the key that was `valid_from ≤ accepted_at` and `valid_until > accepted_at`

---

## 4. Dual Timestamps

Every commit has two distinct timestamps that must never be conflated:

| Field | Set by | Meaning | Part of signed envelope |
|-------|--------|---------|------------------------|
| `client_timestamp` | Agent | What the agent asserted | Yes |
| `accepted_at` | Server ledger | When DarkMatter accepted the commit | No |

The `accepted_at` timestamp is used in the Merkle leaf envelope (§5).
The `client_timestamp` is used in the commit envelope (§2) and is part of the signed surface.

---

## 5. Merkle Leaf Format v1

Each log entry becomes a leaf in the RFC 6962 Merkle tree.
The leaf input is a canonical **log entry envelope** that binds the commit to its position.

### Leaf envelope schema

```json
{
  "accepted_at":    "<ISO-8601 UTC, seconds precision>",
  "commit_id":      "<ctx_...>",
  "integrity_hash": "<64-char lowercase hex, NO sha256: prefix>",
  "log_position":   <integer>
}
```

Note: keys are sorted alphabetically — `accepted_at`, `commit_id`, `integrity_hash`, `log_position`.

### Leaf hash computation (RFC 6962 §2.1)

```
leaf_canonical = canonical(leaf_envelope)
leaf_hash      = SHA-256( 0x00 || UTF-8(leaf_canonical) )
```

The `0x00` domain separation prefix prevents second-preimage attacks (leaf vs internal node).

### Internal node hash

```
node_hash = SHA-256( 0x01 || left_hash_bytes || right_hash_bytes )
```

Odd leaves are promoted unchanged (RFC 6962 §2.1 — no duplication).

### Test vectors

All 11 Merkle vectors in `merkle_test_vectors.json` MUST pass.
Covers: single leaf, two leaves, three leaves (odd), five leaves, inclusion proofs, invalid proofs.

---

## 6. Checkpoint Format v3

Checkpoints are signed periodic snapshots of the Merkle tree state.
They are published externally (GitHub) and are the basis for offline verification.

### Schema

```json
{
  "schema_version":     "3",
  "checkpoint_id":      "cp_<ms>_<hex>",
  "tree_root":          "<64-char hex>",
  "tree_size":          <integer>,
  "log_root":           "<64-char hex>",
  "log_position":       <integer>,
  "timestamp":          "<ISO-8601 UTC seconds>",
  "previous_cp_id":     "<cp_...> | null",
  "previous_tree_root": "<64-char hex> | null",
  "server_sig":         "<hex Ed25519 signature>"
}
```

### Signing

The server signs the canonical form of the checkpoint object (excluding `server_sig`):

```
message    = canonical(checkpoint_without_sig)
server_sig = Ed25519_sign( server_private_key, UTF-8(message) )
```

---

## 7. Proof Receipt Format

Every accepted commit returns a proof receipt in `_proof`:

```json
{
  "log_position":    <integer>,
  "leaf_hash":       "<64-char hex>",
  "tree_root":       "<64-char hex>",
  "tree_size":       <integer>,
  "accepted_at":     "<ISO-8601 UTC seconds>",
  "client_timestamp": "<ISO-8601 UTC seconds>",
  "inclusion_proof": {
    "leaf_index": <integer>,
    "tree_size":  <integer>,
    "proof": [
      { "hash": "<64-char hex>", "direction": "left" | "right" }
    ]
  },
  "proof_status":    "pending | included | checkpointed | checkpointed_published | proof_unavailable",
  "pubkey_url":      "https://darkmatterhub.ai/api/log/pubkey",
  "checkpoint_url":  "https://darkmatterhub.ai/api/log/checkpoint",
  "verify_url":      "https://darkmatterhub.ai/api/log/proof/<commit_id>"
}
```

---

## 8. Export Bundle Format v3.0

Export bundles are self-sufficient — they contain everything needed for offline verification.

### Required fields

| Field | Contents |
|-------|----------|
| `_spec.bundle_version` | `"3.0"` |
| `_spec.spec_url` | Link to this spec |
| `_spec.verifier_url` | Link to `verify_darkmatter_chain.py` |
| `metadata` | Chain info: ctx_id, length, lineage_root |
| `integrity` | chain_intact, root/tip hashes, chain_hash |
| `checkpoint` | Latest signed checkpoint (null if none yet) |
| `server_pubkey` | DarkMatter server Ed25519 public key PEM |
| `commits` | Ordered commits, each with `_proof` receipt |
| `export_hash` | SHA-256 of entire bundle |

---

## 9. Verifier Behavior

The offline verifier (`verify_darkmatter_chain.py`) checks four things in order:

| Phase | Check | Default | Flag to skip |
|-------|-------|---------|-------------|
| Phase 1 | Chain structure: payload hashes + integrity chain | Required | `--legacy` |
| Phase 2 | Agent signatures (if public keys provided) | Optional | — |
| Phase 2 | Checkpoint signature (if checkpoint provided) | Optional | — |
| Phase 3 | Merkle inclusion proofs (if `_proof` in export) | Checked if present | `--skip-proof` |
| Phase 3.5 | Checkpoint consistency (if two checkpoints provided) | Optional | — |

Exit codes: `0` = verified, `1` = failed, `2` = malformed input.

Strict mode (default): missing `payload_hash` or `integrity_hash` = broken.
Legacy mode (`--legacy`): missing hashes are skipped with a warning.

---

## 10. Spec Versioning

- This document is `spec_version: "1.0"`, frozen 2026-04-09
- Every commit records its `spec_version`
- Verifiers must use the spec version from the commit, not the current version
- New spec versions are published at `https://darkmatterhub.ai/docs#integrity-spec`
- Breaking changes require a new major version; additive changes get a minor version
- Spec versions are stored in the `spec_versions` table in Supabase

---

## Appendix: Public API Surface (verification endpoints, no auth required)

| Endpoint | Returns |
|----------|---------|
| `GET /api/log/pubkey` | Server Ed25519 public key PEM |
| `GET /api/log/checkpoint` | Latest signed checkpoint |
| `GET /api/log/checkpoints?limit=N` | Recent checkpoints |
| `GET /api/log/proof/:commitId` | Inclusion proof for any commit |
| `GET /api/log/consistency?from=&to=` | Checkpoint consistency proof |
| `GET /api/log/verify?from=N&to=M` | Log position range consistency |
| `GET /api/agents/:agentId/pubkey?at=<ISO>` | Agent public key at a point in time |
