#!/usr/bin/env python3
"""
verify_darkmatter_chain.py
Independent verification of DarkMatter chains — no SDK required.

Usage:
  curl "https://darkmatterhub.ai/chain/share_xxx/export" | python verify_darkmatter_chain.py
  python verify_darkmatter_chain.py chain.json
"""

import sys
import json
import hashlib


def canonical_json(obj: dict) -> str:
    """Match DarkMatter's canonical JSON: sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))


def verify_chain(data: dict) -> bool:
    commits = data['chain']['commits']
    errors = []

    for i, commit in enumerate(commits):
        # 1. Verify parent linkage
        if i == 0:
            if commit['parent_ctx_id'] is not None:
                errors.append(f"Step {i}: root should have null parent")
        else:
            expected_parent = commits[i - 1]['ctx_id']
            if commit['parent_ctx_id'] != expected_parent:
                errors.append(
                    f"Step {i}: parent mismatch. "
                    f"Expected {expected_parent}, got {commit['parent_ctx_id']}"
                )

        # 2. Verify ctx_id is derived from content hash
        preimage = canonical_json({
            'parent_ctx_id': commit['parent_ctx_id'],
            'payload_hash': commit['payload_hash'],
            'timestamp': commit['timestamp'],
            'agent_id': commit['agent_id'],
            'model': commit['model']
        })
        computed_hash = hashlib.sha256(preimage.encode()).hexdigest()

        # ctx_id format: ctx_{timestamp}_{hash_suffix}
        # Verify the hash suffix matches
        ctx_hash_suffix = commit['ctx_id'].split('_')[-1]
        if not computed_hash.startswith(ctx_hash_suffix) and not computed_hash.endswith(ctx_hash_suffix):
            # Check if it's embedded anywhere (depends on your ID format)
            if ctx_hash_suffix not in computed_hash:
                errors.append(
                    f"Step {i}: hash mismatch. "
                    f"ctx_id suffix {ctx_hash_suffix} not found in computed {computed_hash[:16]}..."
                )

    # 3. Verify chain hash
    chain_preimage = '\n'.join(
        canonical_json({
            'ctx_id': c['ctx_id'],
            'parent_ctx_id': c['parent_ctx_id'],
            'payload_hash': c['payload_hash']
        })
        for c in commits
    )
    computed_chain_hash = 'sha256:' + hashlib.sha256(chain_preimage.encode()).hexdigest()
    expected_chain_hash = data['verification']['chain_hash']

    if computed_chain_hash != expected_chain_hash:
        errors.append(
            f"Chain hash mismatch. Expected {expected_chain_hash}, got {computed_chain_hash}"
        )

    # Report
    print(f"Chain: {data['chain']['chain_id']}")
    print(f"Commits: {len(commits)}")
    print(f"Root: {data['chain']['root_ctx_id']}")
    print(f"Tip: {data['chain']['tip_ctx_id']}")
    print()

    if errors:
        print("❌ VERIFICATION FAILED")
        for e in errors:
            print(f"  - {e}")
        return False
    else:
        print("✓ Chain integrity verified")
        print(f"✓ All {len(commits)} commits linked correctly")
        print(f"✓ Chain hash matches: {expected_chain_hash[:32]}...")
        return True


if __name__ == '__main__':
    if len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    success = verify_chain(data)
    sys.exit(0 if success else 1)
