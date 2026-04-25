"""
DarkMatter Python SDK v1.3.0
Independent verification and audit layer for AI agent decisions.

pip install darkmatter-sdk

Quickstart:
    import darkmatter as dm

    dm.configure(api_key="dm_sk_...")
    ctx = dm.commit(payload={"input": "...", "output": "..."})
    print(ctx["verify_url"])

L3 non-repudiation:
    dm.configure(
        api_key = "dm_sk_...",
        signing = dm.SigningConfig(
            key_id           = "my-key",
            private_key_path = "./my-key.pem",
        ),
    )
    ctx = dm.commit(payload={...}, completeness_claim=True)

Auto-instrumentation:
    from darkmatter.integrations.anthropic import Anthropic
    from darkmatter.integrations.openai import OpenAI

Docs: https://darkmatterhub.ai/docs
"""

__version__ = "1.3.0"

from .client import (
    configure,
    commit,
    verify,
    replay,
    fork,
    diff,
    bundle,
    me,
    SigningConfig,
    register_signing_key,
    list_signing_keys,
    revoke_signing_key,
    run_envelope_test_vectors,
)

from .exceptions import DarkMatterError, AuthError, NotFoundError

__all__ = [
    # Configuration
    "configure",
    # Core operations
    "commit",
    "verify",
    "replay",
    "fork",
    "diff",
    "bundle",
    "me",
    # L3 signing
    "SigningConfig",
    "register_signing_key",
    "list_signing_keys",
    "revoke_signing_key",
    "run_envelope_test_vectors",
    # Exceptions
    "DarkMatterError",
    "AuthError",
    "NotFoundError",
    # Version
    "__version__",
]
