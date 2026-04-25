"""
darkmatter.integrations.openai
──────────────────────────────────────────────────────────────────────────────
Drop-in wrapper for the OpenAI SDK that auto-commits every
chat.completions.create() call to DarkMatter.

Usage:
    from darkmatter.integrations.openai import OpenAI

    client = OpenAI(
        dm_api_key = "dm_sk_...",   # or set DARKMATTER_API_KEY
        api_key    = "sk-...",       # standard OpenAI key
        # dm_agent_id = "dm_...",   # optional
    )

    response = client.chat.completions.create(
        model    = "gpt-4o",
        messages = [{"role": "user", "content": "Should I approve this refund?"}],
    )

Every call is automatically committed to DarkMatter.
Tool calls within a response are committed as separate child records.

Coverage assertion:
    Each commit carries a scoped coverage assertion:
    "The wrapper observed this openai.chat.completions.create() call completely."
    This is NOT an assertion about the broader agent workflow or session.
    For full workflow coverage, instrument every call in your agent loop.

DarkMatter-specific kwargs (all prefixed dm_):
    dm_api_key     str             DarkMatter API key (or set DARKMATTER_API_KEY)
    dm_agent_id    str             DarkMatter agent ID — optional (or set DARKMATTER_AGENT_ID)
    dm_signing     SigningConfig   L3 signing config (optional)
    dm_event_type  str             Event type label (default: "openai.chat.completions.create")
    dm_metadata    dict            Extra metadata to attach to every commit
    dm_auto_commit bool            Set False to disable auto-commit (default: True)
    dm_commit_tools bool           Set False to skip tool call commits (default: True)
    dm_async       bool            Send commits in background thread (default: True)
    dm_debug       bool            Print full traceback on commit errors (default: False)
    dm_host        str             DarkMatter host (default: https://darkmatterhub.ai)
"""

from __future__ import annotations

import os
import time
import threading
import logging
from typing import Any

logger = logging.getLogger('darkmatter')


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

def _extract_text(message) -> str:
    """Extract plain text from an OpenAI ChatCompletionMessage."""
    if message is None:
        return ''
    content = getattr(message, 'content', None)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return '\n'.join(
            p.get('text', '') if isinstance(p, dict) else getattr(p, 'text', '')
            for p in content
        )
    return ''


def _extract_tool_calls(message) -> list[dict]:
    """Extract tool_calls from an OpenAI ChatCompletionMessage."""
    tool_calls = getattr(message, 'tool_calls', None) or []
    result = []
    for tc in tool_calls:
        fn = getattr(tc, 'function', None)
        if fn is None:
            continue
        try:
            import json
            args = json.loads(fn.arguments) if fn.arguments else {}
        except Exception:
            args = {'_raw': fn.arguments}
        result.append({
            'tool_call_id': tc.id,
            'name':         fn.name,
            'input':        args,
        })
    return result


def _messages_to_input(messages: list) -> str:
    """Summarise conversation messages into a readable input string."""
    parts = []
    for m in messages:
        if isinstance(m, dict):
            role    = m.get('role', 'user')
            content = m.get('content', '')
        else:
            role    = getattr(m, 'role', 'user')
            content = getattr(m, 'content', '')
        if isinstance(content, str) and content:
            parts.append(f'[{role}] {content[:500]}')
        elif isinstance(content, list):
            text = ' '.join(
                p.get('text', '') if isinstance(p, dict) else getattr(p, 'text', '')
                for p in content if p
            )
            if text:
                parts.append(f'[{role}] {text[:500]}')
    return '\n'.join(parts[-4:])  # last 4 turns


def _build_metadata(model: str, response, extra: dict | None) -> dict:
    """Build metadata dict from model + response usage + extra."""
    meta = {
        'model':      model,
        'wrapper':    'darkmatter.integrations.openai',
        'sdk_version': _sdk_version(),
    }
    usage = getattr(response, 'usage', None)
    if usage:
        if hasattr(usage, 'prompt_tokens'):
            meta['input_tokens']  = usage.prompt_tokens
        if hasattr(usage, 'completion_tokens'):
            meta['output_tokens'] = usage.completion_tokens
        if hasattr(usage, 'total_tokens'):
            meta['total_tokens']  = usage.total_tokens
    choices = getattr(response, 'choices', [])
    if choices:
        meta['finish_reason'] = getattr(choices[0], 'finish_reason', None)
    if extra:
        meta.update(extra)
    return meta


def _sdk_version() -> str:
    try:
        import openai
        return openai.__version__
    except Exception:
        return 'unknown'


def _commit_openai_call(cfg: dict, kwargs: dict, response, elapsed_ms: int):
    """
    Shared commit helper used by both sync and async wrappers.
    Never raises — commit failures must not affect the caller.
    """
    try:
        dm  = _get_dm()

        model    = kwargs.get('model') or getattr(response, 'model', 'unknown')
        messages = kwargs.get('messages', [])

        # Extract input / output
        input_text  = _messages_to_input(messages)
        choices     = getattr(response, 'choices', [])
        first       = choices[0] if choices else None
        message     = getattr(first, 'message', None)
        output_text = _extract_text(message)
        tool_calls  = _extract_tool_calls(message)

        payload = {
            'input':         input_text,
            'output':        output_text,
            'model':         model,
            'elapsed_ms':    elapsed_ms,
            'finish_reason': getattr(first, 'finish_reason', None),
        }
        if tool_calls:
            payload['tool_calls'] = tool_calls

        metadata = _build_metadata(
            model    = model,
            response = response,
            extra    = cfg.get('dm_metadata'),
        )

        # Build commit kwargs — dm_agent_id is optional
        commit_kwargs = dict(
            payload            = payload,
            metadata           = metadata,
            event_type         = cfg.get('dm_event_type', 'openai.chat.completions.create'),
            completeness_claim = True,   # scoped to this observed call
            signing            = cfg.get('dm_signing'),
        )
        if cfg.get('dm_agent_id'):
            commit_kwargs['to_agent_id'] = cfg['dm_agent_id']

        # Main commit — capture returned ID for parent linkage
        result = dm.commit(**commit_kwargs)
        parent_id = (result or {}).get('id')

        # Tool call child commits — linked to parent
        if tool_calls and cfg.get('dm_commit_tools', True):
            for tc in tool_calls:
                child_kwargs = dict(
                    payload    = {
                        'tool_name':    tc['name'],
                        'tool_call_id': tc['tool_call_id'],
                        'input':        tc['input'],
                    },
                    metadata   = {'model': model, 'wrapper': 'darkmatter.integrations.openai'},
                    event_type = 'openai.tool_call',
                    signing    = cfg.get('dm_signing'),
                )
                if cfg.get('dm_agent_id'):
                    child_kwargs['to_agent_id'] = cfg['dm_agent_id']
                if parent_id:
                    child_kwargs['parent_id'] = parent_id
                dm.commit(**child_kwargs)

    except Exception as e:
        if cfg.get('dm_debug'):
            import traceback
            traceback.print_exc()
        else:
            logger.debug('[DarkMatter] commit error: %s', e)


# ── Instrumented Completions resource ────────────────────────────────────────

class _InstrumentedCompletions:
    def __init__(self, completions_resource, wrapper_config: dict):
        self._completions = completions_resource
        self._cfg         = wrapper_config

    def create(self, **kwargs) -> Any:
        """
        Wraps chat.completions.create() — commits request + response to DarkMatter.
        All kwargs pass through unchanged to the underlying OpenAI client.
        """
        cfg = self._cfg

        if not cfg.get('dm_auto_commit', True):
            return self._completions.create(**kwargs)

        t0       = time.time()
        response = self._completions.create(**kwargs)
        elapsed  = int((time.time() - t0) * 1000)

        if cfg.get('dm_async', True):
            t = threading.Thread(
                target=_commit_openai_call,
                args=(cfg, kwargs, response, elapsed),
                daemon=True,
            )
            t.start()
        else:
            _commit_openai_call(cfg, kwargs, response, elapsed)

        return response


class _InstrumentedChat:
    def __init__(self, chat_resource, wrapper_config: dict):
        self._chat        = chat_resource
        self.completions  = _InstrumentedCompletions(
            chat_resource.completions, wrapper_config
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


# ── Drop-in OpenAI client ─────────────────────────────────────────────────────

class OpenAI:
    """
    Drop-in replacement for openai.OpenAI that auto-commits every
    chat.completions.create() call to DarkMatter.

    All standard OpenAI kwargs pass through unchanged.
    DarkMatter configuration is passed via dm_* kwargs.

    Example:
        from darkmatter.integrations.openai import OpenAI

        client = OpenAI(
            dm_api_key = "dm_sk_...",   # or set DARKMATTER_API_KEY
            api_key    = "sk-...",       # standard OpenAI key
            # Optional:
            # dm_agent_id = "dm_...",   # or set DARKMATTER_AGENT_ID
        )
        response = client.chat.completions.create(
            model    = "gpt-4o",
            messages = [{"role": "user", "content": "Hello"}],
        )
    """

    def __init__(self, **kwargs):
        import openai as _openai

        dm_keys          = [k for k in kwargs if k.startswith('dm_')]
        openai_kwargs    = {k: v for k, v in kwargs.items() if k not in dm_keys}

        dm_api_key  = kwargs.get('dm_api_key')  or os.environ.get('DARKMATTER_API_KEY')
        dm_agent_id = kwargs.get('dm_agent_id') or os.environ.get('DARKMATTER_AGENT_ID')
        dm_signing  = kwargs.get('dm_signing')

        if not dm_api_key:
            raise ValueError(
                'DarkMatter API key required. Pass dm_api_key= or set DARKMATTER_API_KEY.'
            )
        # dm_agent_id is optional — commits work without it

        dm = _get_dm()
        dm.configure(api_key=dm_api_key, signing=dm_signing)

        self._dm_cfg = {
            'dm_api_key':      dm_api_key,
            'dm_agent_id':     dm_agent_id,
            'dm_signing':      dm_signing,
            'dm_event_type':   kwargs.get('dm_event_type', 'openai.chat.completions.create'),
            'dm_metadata':     kwargs.get('dm_metadata'),
            'dm_auto_commit':  kwargs.get('dm_auto_commit', True),
            'dm_commit_tools': kwargs.get('dm_commit_tools', True),
            'dm_async':        kwargs.get('dm_async', True),
            'dm_debug':        kwargs.get('dm_debug', False),
        }

        self._client  = _openai.OpenAI(**openai_kwargs)
        self.chat     = _InstrumentedChat(self._client.chat, self._dm_cfg)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


# ── AsyncOpenAI wrapper ───────────────────────────────────────────────────────

class AsyncOpenAI:
    """
    Async drop-in replacement for openai.AsyncOpenAI.
    Commits are sent in a background thread — no async overhead.
    """

    def __init__(self, **kwargs):
        import openai as _openai

        dm_keys       = [k for k in kwargs if k.startswith('dm_')]
        openai_kwargs = {k: v for k, v in kwargs.items() if k not in dm_keys}

        dm_api_key  = kwargs.get('dm_api_key')  or os.environ.get('DARKMATTER_API_KEY')
        dm_agent_id = kwargs.get('dm_agent_id') or os.environ.get('DARKMATTER_AGENT_ID')
        dm_signing  = kwargs.get('dm_signing')

        if not dm_api_key:  raise ValueError('DarkMatter API key required.')
        # dm_agent_id is optional

        dm = _get_dm()
        dm.configure(api_key=dm_api_key, signing=dm_signing)

        self._dm_cfg = {
            'dm_api_key':      dm_api_key,
            'dm_agent_id':     dm_agent_id,
            'dm_signing':      dm_signing,
            'dm_event_type':   kwargs.get('dm_event_type', 'openai.chat.completions.create'),
            'dm_metadata':     kwargs.get('dm_metadata'),
            'dm_auto_commit':  kwargs.get('dm_auto_commit', True),
            'dm_commit_tools': kwargs.get('dm_commit_tools', True),
            'dm_async':        True,
            'dm_debug':        kwargs.get('dm_debug', False),
        }

        self._client = _openai.AsyncOpenAI(**openai_kwargs)
        self.chat    = _AsyncInstrumentedChat(self._client.chat, self._dm_cfg)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


class _AsyncInstrumentedChat:
    def __init__(self, chat_resource, wrapper_config: dict):
        self._chat        = chat_resource
        self.completions  = _AsyncInstrumentedCompletions(
            chat_resource.completions, wrapper_config
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._chat, name)


class _AsyncInstrumentedCompletions:
    def __init__(self, completions_resource, wrapper_config: dict):
        self._completions = completions_resource
        self._cfg         = wrapper_config

    async def create(self, **kwargs) -> Any:
        if not self._cfg.get('dm_auto_commit', True):
            return await self._completions.create(**kwargs)

        t0       = time.time()
        response = await self._completions.create(**kwargs)
        elapsed  = int((time.time() - t0) * 1000)

        t = threading.Thread(
            target=_commit_openai_call,
            args=(self._cfg, kwargs, response, elapsed),
            daemon=True,
        )
        t.start()

        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._completions, name)


# ── Roadmap ───────────────────────────────────────────────────────────────────
# Next: wrap client.responses.create() — OpenAI's newer API surface.
# Same pattern: intercept request/response, commit to DarkMatter.
# Add as _InstrumentedResponses alongside _InstrumentedCompletions.
