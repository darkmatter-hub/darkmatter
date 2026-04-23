# DarkMatter Python SDK

**Install:** `pip install darkmatter-sdk`  
**PyPI:** https://pypi.org/project/darkmatter-sdk/  
**Docs:** https://darkmatterhub.ai/docs

---

## Quickstart (L1/L2)

```python
import darkmatter as dm

dm.configure(api_key="dm_sk_...")

ctx = dm.commit(
    to_agent_id="dm_your_agent_id",
    payload={"input": "approve refund?", "output": "approved"},
)
print(ctx["verify_url"])
```

---

## L3 Non-repudiation (customer-signed)

L3 means DarkMatter **cannot forge your records** — every commit is signed
with a key only you hold, before it reaches DarkMatter's servers.

### One-time setup

```bash
# Generate Ed25519 keypair
openssl genpkey -algorithm ed25519 -out my-signing-key.pem
openssl pkey -in my-signing-key.pem -pubout -out my-signing-key.pub
```

```python
import darkmatter as dm

dm.configure(api_key="dm_sk_...")

# Register your public key once
dm.register_signing_key(
    key_id="my-signing-key",
    public_key_path="my-signing-key.pub",
)
```

```bash
# Add to .env — then dm.commit() is identical, every commit is L3
DARKMATTER_SIGNING_MODE=customer
DARKMATTER_SIGNING_KEY_ID=my-signing-key
DARKMATTER_SIGNING_KEY_PATH=./my-signing-key.pem
```

### Usage (unchanged after setup)

```python
import darkmatter as dm

# SigningConfig loaded automatically from env
dm.configure(
    api_key="dm_sk_...",
    signing=dm.SigningConfig.from_env(),   # reads DARKMATTER_SIGNING_* vars
)

# commit() is identical — L3 attestation added transparently
ctx = dm.commit(
    to_agent_id="dm_your_agent_id",
    payload={"input": "approve refund?", "output": "approved"},
    metadata={"model": "claude-sonnet-4-6"},
)
print(ctx["assurance_level"])   # "L3"
print(ctx["verify_url"])        # shows L3 badge — signed by your key
```

### Per-call override

```python
cfg = dm.SigningConfig(
    key_id="my-signing-key",
    private_key_path="my-signing-key.pem",
)

ctx = dm.commit(
    to_agent_id="dm_agent_id",
    payload={...},
    signing=cfg,   # override for this call only
)
```

---

## Key management

```python
import darkmatter as dm

dm.configure(api_key="dm_sk_...")

# List registered keys
keys = dm.list_signing_keys()

# Revoke a key (existing records unaffected)
dm.revoke_signing_key("my-signing-key")
```

---

## Verify test vectors (SDK release gate)

Before any SDK release, all 3 envelope test vectors must pass:

```python
import darkmatter as dm

result = dm.run_envelope_test_vectors("../../test-vectors-envelope-v1.json")
assert result["passed"], result["results"]
print("All vectors passed")
```

---

## Envelope spec

L3 signing implements `ENVELOPE_SPEC_V1.md` at the repo root.
Canonical serialization: keys sorted recursively, no whitespace, UTF-8, no escaped Unicode.

```
sha256(canonical_json(envelope))  →  signed with Ed25519 private key
```

---

## Environment variables

| Variable | Description |
|---|---|
| `DARKMATTER_API_KEY` | Your DarkMatter API key (`dm_sk_...`) |
| `DARKMATTER_AGENT_ID` | Your agent ID (`dm_...`) |
| `DARKMATTER_SIGNING_MODE` | `customer` to enable L3 |
| `DARKMATTER_SIGNING_KEY_ID` | Key identifier (must match registered key) |
| `DARKMATTER_SIGNING_KEY_PATH` | Path to Ed25519 private key PEM |
| `DARKMATTER_SIGNING_KEY_PEM` | Inline PEM string (alternative to path) |
