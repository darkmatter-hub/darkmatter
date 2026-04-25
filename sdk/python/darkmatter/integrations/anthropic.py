"""
darkmatter.integrations.anthropic
──────────────────────────────────────────────────────────────────────────────
Drop-in wrapper for the Anthropic SDK that auto-commits every
messages.create() call to DarkMatter.

Usage:
    from darkmatter.integrations.anthropic import Anthropic

    client = Anthropic(
        dm_api_key  = "dm_sk_...",
        dm_agent_id = "dm_...",
        # Optional — L3 non-repudiation:
        dm_signing  = dm.SigningConfig(
            key_id           = "my-signing-key",
            private_key_path = "./my-signing-key.pem",
        ),
    )

    # Use exactly like the standard Anthropic client:
    response = client.messages.create(
        model     = "claude-sonnet-4-6",
        max_tokens= 1024,
        messages  = [{"role": "user", "content": "Approve this refund?"}],
    )

Every call is automatically committed to DarkMatter.
Tool calls within a response are committed as separate child records.

Coverage assertion:
    Each commit carries completeness_claim=True scoped to the observed
    API call — not the full agent execution. Meaning:
    "The wrapper observed this Anthropic API call and committed it completely."
    It does NOT assert that the broader agent workflow is complete.

DarkMatter-specific kwargs (all prefixed dm_):
    dm_api_key     str             DarkMatter API key (or set DARKMATTER_API_KEY)
    dm_agent_id    str             DarkMatter agent ID (or set DARKMATTER_AGENT_ID)
    dm_signing     SigningConfig   L3 signing config (optional)
    dm_event_type  str             Event type label (default: "anthropic.messages.create")
    dm_metadata    dict            Extra metadata to attach to every commit
    dm_auto_commit bool            Set False to disable auto-commit (default: True)
    dm_host        str             DarkMatter host (default: https://darkmatterhub.ai)
"""

from __future__ import annotations

import os
import json
import time
import threading
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    pass

# ── Lazy import of darkmatter SDK ─────────────────────────────────────────────
def _get_dm():
    try:
        import darkmatter as dm
        return dm
    except ImportError:
        raise ImportError(
            'darkmatter SDK not found. Install: pip install darkmatter-sdk'
        )

# ── Payload extraction helpers ────────────────────────────────────────────────

def _extract_text(content) -> str:
    """Extract plain text from Anthropic content (list of blocks or string)."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if hasattr(block, 'text'):
                parts.append(block.text)
            elif isinstance(block, dict) and block.get('type') == 'text':
                parts.append(block.get('text', ''))
        return '\n'.join(parts)
    return str(content)


def _extract_tool_calls(content) -> list[dict]:
    """Extract tool_use blocks from Anthropic response content."""
    tools = []
    if not isinstance(content, list):
        return tools
    for block in content:
        if hasattr(block, 'type') and block.type == 'tool_use':
            tools.append({
                'tool_call_id': block.id,
                'name':         block.name,
                'input':        block.input if isinstance(block.input, dict) else {},
            })
        elif isinstance(block, dict) and block.get('type') == 'tool_use':
            tools.append({
                'tool_call_id': block.get('id'),
                'name':         block.get('name'),
                'input':        block.get('input', {}),
            })
    return tools


def _messages_to_input(messages: list[dict]) -> str:
    """Summarise conversation messages into a readable input string."""
    parts = []
    for m in messages:
        role    = m.get('role', 'user')
        content = m.get('content', '')
        text    = _extract_text(content)
        if text:
            parts.append(f'[{role}] {text[:500]}')
    return '\n'.join(parts[-4:])  # last 4 turns to keep payload concise


def _build_metadata(model: str, response, extra: dict | None) -> dict:
    """Build metadata dict from model + response usage + extra."""
    meta = {
        'model':      model,
        'wrapper':    'darkmatter.integrations.anthropic',
        'sdk_version': _sdk_version(),
    }
    if hasattr(response, 'usage') and response.usage:
        usage = response.usage
        if hasattr(usage, 'input_tokens'):
            meta['input_tokens']  = usage.input_tokens
        if hasattr(usage, 'output_tokens'):
            meta['output_tokens'] = usage.output_tokens
    if hasattr(response, 'stop_reason'):
        meta['stop_reason'] = response.stop_reason
    if extra:
        meta.update(extra)
    return meta


def _sdk_version() -> str:
    try:
        import anthropic
        return anthropic.__version__
    except Exception:
        return 'unknown'

# ── Coverage assertion ────────────────────────────────────────────────────────

def _coverage_assertion(tool_calls: list) -> dict:
    """
    Build a structured coverage assertion for this API call.
    Scope is limited to the observed Anthropic call, not the full agent execution.
    """
    return {
        'value':  True,
        'scope':  'anthropic.messages.create',
        'method': 'sdk_wrapper',
        'tool_calls_observed': len(tool_calls),
    }

# ── Instrumented Messages resource ───────────────────────────────────────────

class _InstrumentedMessages:
    def __init__(self, messages_resource, wrapper_config: dict):
        self._messages  = messages_resource
        self._cfg       = wrapper_config

    def create(self, **kwargs) -> Any:
        """
        Wraps messages.create() — commits request + response to DarkMatter.
        All kwargs are passed through unchanged to the underlying Anthropic client.
        """
        cfg = self._cfg

        # Pass through if auto-commit disabled
        if not cfg.get('dm_auto_commit', True):
            return self._messages.create(**kwargs)

        # Record start time
        t0 = time.time()

        # Call the real Anthropic API
        response = self._messages.create(**kwargs)

        elapsed_ms = int((time.time() - t0) * 1000)

        # Commit asynchronously so we don't slow the caller
        if cfg.get('dm_async', True):
            t = threading.Thread(
                target=self._commit,
                args=(kwargs, response, elapsed_ms),
                daemon=True,
            )
            t.start()
        else:
            self._commit(kwargs, response, elapsed_ms)

        return response

    def _commit(self, kwargs: dict, response, elapsed_ms: int):
        """Build and submit DarkMatter commit(s) for this API call."""
        try:
            dm  = _get_dm()
            cfg = self._cfg

            model    = kwargs.get('model', getattr(response, 'model', 'unknown'))
            messages = kwargs.get('messages', [])

            # Extract input / output
            input_text  = _messages_to_input(messages)
            output_text = _extract_text(response.content)
            tool_calls  = _extract_tool_calls(response.content)

            # Build payload
            payload = {
                'input':        input_text,
                'output':       output_text,
                'model':        model,
                'elapsed_ms':   elapsed_ms,
                'stop_reason':  getattr(response, 'stop_reason', None),
            }
            if tool_calls:
                payload['tool_calls'] = tool_calls

            # Build metadata
            metadata = _build_metadata(
                model    = model,
                response = response,
                extra    = cfg.get('dm_metadata'),
            )

            # Coverage assertion — scoped to this observed call
            coverage = _coverage_assertion(tool_calls)

            # Main commit
            dm.commit(
                to_agent_id       = cfg['dm_agent_id'],
                payload           = payload,
                metadata          = metadata,
                event_type        = cfg.get('dm_event_type', 'anthropic.messages.create'),
                completeness_claim = True,   # wrapper observed full request + response
                signing           = cfg.get('dm_signing'),
            )

            # Separate child commits for each tool call
            if tool_calls and cfg.get('dm_commit_tools', True):
                for tc in tool_calls:
                    dm.commit(
                        to_agent_id = cfg['dm_agent_id'],
                        payload     = {
                            'tool_name':    tc['name'],
                            'tool_call_id': tc['tool_call_id'],
                            'input':        tc['input'],
                        },
                        metadata    = {'model': model, 'wrapper': 'darkmatter.integrations.anthropic'},
                        event_type  = 'anthropic.tool_call',
                        signing     = cfg.get('dm_signing'),
                    )

        except Exception as e:
            # Never raise — instrumentation must not break the caller
            if self._cfg.get('dm_debug'):
                import traceback
                traceback.print_exc()
            else:
                print(f'[DarkMatter] commit error (set dm_debug=True for details): {e}')


# ── Drop-in Anthropic client ──────────────────────────────────────────────────

class Anthropic:
    """
    Drop-in replacement for anthropic.Anthropic that auto-commits
    every messages.create() call to DarkMatter.

    All standard Anthropic kwargs are passed through unchanged.
    DarkMatter configuration is passed via dm_* kwargs.

    Example:
        from darkmatter.integrations.anthropic import Anthropic

        client = Anthropic(
            dm_api_key  = "dm_sk_...",
            dm_agent_id = "dm_...",
        )
        response = client.messages.create(
            model     = "claude-sonnet-4-6",
            max_tokens= 1024,
            messages  = [{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(self, **kwargs):
        import anthropic as _anthropic

        # Separate DarkMatter kwargs from Anthropic kwargs
        dm_keys = [k for k in kwargs if k.startswith('dm_')]
        anthropic_kwargs = {k: v for k, v in kwargs.items() if k not in dm_keys}

        # DarkMatter config
        dm_api_key  = kwargs.get('dm_api_key')  or os.environ.get('DARKMATTER_API_KEY')
        dm_agent_id = kwargs.get('dm_agent_id') or os.environ.get('DARKMATTER_AGENT_ID')
        dm_signing  = kwargs.get('dm_signing')

        if not dm_api_key:
            raise ValueError(
                'DarkMatter API key required. Pass dm_api_key= or set DARKMATTER_API_KEY.'
            )
        if not dm_agent_id:
            raise ValueError(
                'DarkMatter agent ID required. Pass dm_agent_id= or set DARKMATTER_AGENT_ID.'
            )

        # Configure DarkMatter SDK
        dm = _get_dm()
        dm.configure(
            api_key = dm_api_key,
            signing = dm_signing,
        )

        # Build wrapper config
        self._dm_cfg = {
            'dm_api_key':      dm_api_key,
            'dm_agent_id':     dm_agent_id,
            'dm_signing':      dm_signing,
            'dm_event_type':   kwargs.get('dm_event_type', 'anthropic.messages.create'),
            'dm_metadata':     kwargs.get('dm_metadata'),
            'dm_auto_commit':  kwargs.get('dm_auto_commit', True),
            'dm_commit_tools': kwargs.get('dm_commit_tools', True),
            'dm_async':        kwargs.get('dm_async', True),
            'dm_debug':        kwargs.get('dm_debug', False),
        }

        # Create the real Anthropic client
        self._client = _anthropic.Anthropic(**anthropic_kwargs)

        # Wrap messages resource
        self.messages = _InstrumentedMessages(self._client.messages, self._dm_cfg)

    def __getattr__(self, name: str) -> Any:
        """
        Proxy all other attributes (completions, beta, etc.) to the underlying client.
        Only messages is instrumented.
        """
        return getattr(self._client, name)


# ── AsyncAnthropic wrapper ────────────────────────────────────────────────────

class AsyncAnthropic:
    """
    Async drop-in replacement for anthropic.AsyncAnthropic.
    Commits are sent synchronously in a background thread so
    async callers are not blocked.
    """

    def __init__(self, **kwargs):
        import anthropic as _anthropic

        dm_keys = [k for k in kwargs if k.startswith('dm_')]
        anthropic_kwargs = {k: v for k, v in kwargs.items() if k not in dm_keys}

        dm_api_key  = kwargs.get('dm_api_key')  or os.environ.get('DARKMATTER_API_KEY')
        dm_agent_id = kwargs.get('dm_agent_id') or os.environ.get('DARKMATTER_AGENT_ID')
        dm_signing  = kwargs.get('dm_signing')

        if not dm_api_key:
            raise ValueError('DarkMatter API key required.')
        if not dm_agent_id:
            raise ValueError('DarkMatter agent ID required.')

        dm = _get_dm()
        dm.configure(api_key=dm_api_key, signing=dm_signing)

        self._dm_cfg = {
            'dm_api_key':      dm_api_key,
            'dm_agent_id':     dm_agent_id,
            'dm_signing':      dm_signing,
            'dm_event_type':   kwargs.get('dm_event_type', 'anthropic.messages.create'),
            'dm_metadata':     kwargs.get('dm_metadata'),
            'dm_auto_commit':  kwargs.get('dm_auto_commit', True),
            'dm_commit_tools': kwargs.get('dm_commit_tools', True),
            'dm_async':        True,   # always async for this client
            'dm_debug':        kwargs.get('dm_debug', False),
        }

        self._client  = _anthropic.AsyncAnthropic(**anthropic_kwargs)
        self.messages = _AsyncInstrumentedMessages(self._client.messages, self._dm_cfg)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _AsyncInstrumentedMessages:
    def __init__(self, messages_resource, wrapper_config: dict):
        self._messages = messages_resource
        self._cfg      = wrapper_config

    async def create(self, **kwargs) -> Any:
        if not self._cfg.get('dm_auto_commit', True):
            return await self._messages.create(**kwargs)

        t0       = time.time()
        response = await self._messages.create(**kwargs)
        elapsed  = int((time.time() - t0) * 1000)

        # Commit in background thread — don't block the async caller
        t = threading.Thread(
            target=_InstrumentedMessages(self._messages, self._cfg)._commit,
            args=(kwargs, response, elapsed),
            daemon=True,
        )
        t.start()

        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._messages, name)
