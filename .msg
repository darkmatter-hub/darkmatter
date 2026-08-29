fix: the server ignored every client-computed hash the Python SDK sent

DarkMatter's central claim is that the payload is hashed on the client before
transmission, so the server is a notary that cannot alter what it stores. The
comment above this code says exactly that.

It has never worked. The server read req.body.clientPayloadHash,
clientIntegrityHash, agentSignature and agentPublicKey. The Python SDK posts
payload_hash, integrity_hash, agent_signature and agent_public_key. Nothing
mapped between them, so every value the SDK computed was dropped on arrival.

The consequences follow from that one mismatch. clientPayloadHash was always
null, so the stored hash was always the server's own computation and the notary
property never engaged. hashMismatch was always false, so the cross-check that
exists to catch a lying server could never fire. The Ed25519 signature the SDK
attaches was discarded too.

Production confirms it: zero of nine records carry a client hash, zero
mismatches have ever been recorded, and every record sits at L1.

Fixed on the server rather than in the SDK, deliberately. Every copy of the SDK
already installed starts working immediately, instead of only the ones that
upgrade. Both spellings are accepted, so nothing that works today breaks.

A field-name mismatch fails silently by construction: no error, no warning, just
a value quietly replaced by the server's own. A test now asserts both spellings
are read for all four fields, and it fails if either is removed.

Not addressed here: the JavaScript SDK computes no hash at all, so client-side
hashing is unavailable to those callers regardless of field naming. The site
states the guarantee without qualification, which is a separate correction.
