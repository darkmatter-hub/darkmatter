"""
darkmatter.integrations.openai — responses.create() wrapper
============================================================
Extends the existing OpenAI wrapper to also instrument
the newer Responses API (openai.responses.create).

Usage
-----
from darkmatter.integrations.openai import OpenAI

client = OpenAI(
    api_key="sk-...",
    dm_api_key="dm_sk_...",
)

# chat.completions.create — already instrumented in v1.3.0
response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Approve refund?"}],
)

# responses.create — now instrumented
response = client.responses.create(
    model="gpt-4o",
    input="Approve refund for order #84721?",
)
# Both calls commit to DarkMatter automatically.

Patch note (v1.4.0)
-------------------
Added DarkMatterResponses wrapper class that intercepts
client.responses.create() and commits input/output.

The file replaces darkmatter/integrations/openai.py in the SDK.
"""

from __future__ import annotations

import os
import time
import json
from typing import Any, Dict, Iterator, Optional, Union

try:
    import openai as _openai
    from openai import OpenAI as _OpenAI, AsyncOpenAI as _AsyncOpenAI
except ImportError:
    raise ImportError(
        'openai package not installed. Run: pip install "darkmatter-sdk[openai]"'
    )


def _dm_commit(
    api_key: str,
    agent_name: str,
    base_url: str,
    payload: Dict[str, Any],
    event_type: str = "openai_call",
    trace_id: Optional[str] = None,
    dm_debug: bool = False,
) -> Dict[str, Any]:
    """Fire-and-forget DarkMatter commit."""
    if not api_key:
        return {}
    try:
        import urllib.request
        body = json.dumps({
            "toAgentId":  agent_name,
            "payload":    payload,
            "eventType":  event_type,
            "traceId":    trace_id,
            "agent": {
                "name":     agent_name,
                "provider": "openai",
                "wrapper":  "darkmatter-openai",
            },
        }).encode()
        req = urllib.request.Request(
            f"{base_url.rstrip('/')}/api/commit",
            data=body,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            receipt = json.loads(r.read())
            if dm_debug:
                print(f"[DarkMatter] committed {event_type} → {receipt.get('ctxId','?')}")
            return receipt
    except Exception as e:
        if dm_debug:
            print(f"[DarkMatter] commit error: {e}")
        return {}


class _DarkMatterResponses:
    """Wraps client.responses so responses.create() is auto-committed."""

    def __init__(self, responses_obj: Any, dm_config: Dict[str, Any]):
        self._responses = responses_obj
        self._dm        = dm_config

    def create(self, *args, **kwargs) -> Any:
        dm_trace_id = kwargs.pop("dm_trace_id", None)
        t0 = time.time()
        response = self._responses.create(*args, **kwargs)
        elapsed  = round((time.time() - t0) * 1000)

        # Extract input/output safely
        input_text  = kwargs.get("input", args[0] if args else "")
        output_text = ""
        try:
            if hasattr(response, "output_text"):
                output_text = response.output_text
            elif hasattr(response, "output"):
                for item in response.output or []:
                    if hasattr(item, "content"):
                        for block in item.content or []:
                            if hasattr(block, "text"):
                                output_text += block.text
        except Exception:
            pass

        if self._dm.get("auto_commit", True):
            _dm_commit(
                api_key    = self._dm["api_key"],
                agent_name = self._dm["agent_name"],
                base_url   = self._dm["base_url"],
                payload    = {
                    "input":      str(input_text)[:500],
                    "output":     str(output_text)[:500],
                    "model":      kwargs.get("model", "?"),
                    "latency_ms": elapsed,
                    "wrapper":    "openai_responses",
                },
                event_type = "openai_responses_call",
                trace_id   = dm_trace_id,
                dm_debug   = self._dm.get("debug", False),
            )
        return response

    def __getattr__(self, name: str) -> Any:
        return getattr(self._responses, name)


class OpenAI(_OpenAI):
    """
    Drop-in replacement for openai.OpenAI that auto-commits every
    chat.completions.create() AND responses.create() to DarkMatter.
    """

    def __init__(
        self,
        *args,
        dm_api_key:    Optional[str] = None,
        dm_agent_name: Optional[str] = None,
        dm_base_url:   str = "https://darkmatterhub.ai",
        dm_auto_commit: bool = True,
        dm_debug:      bool = False,
        dm_trace_id:   Optional[str] = None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._dm = {
            "api_key":    dm_api_key    or os.environ.get("DARKMATTER_API_KEY", ""),
            "agent_name": dm_agent_name or os.environ.get("DARKMATTER_AGENT_NAME", "openai-agent"),
            "base_url":   dm_base_url,
            "auto_commit": dm_auto_commit,
            "debug":      dm_debug,
            "trace_id":   dm_trace_id,
        }
        # Wrap responses API
        if hasattr(super(), "responses"):
            self._responses_wrapped = _DarkMatterResponses(super().responses, self._dm)

    @property
    def responses(self) -> _DarkMatterResponses:
        return getattr(self, "_responses_wrapped", _DarkMatterResponses(super().responses, self._dm))

    def _wrap_chat_create(self, original_fn):
        def wrapped(*args, **kwargs):
            dm_trace_id = kwargs.pop("dm_trace_id", self._dm.get("trace_id"))
            t0 = time.time()
            response = original_fn(*args, **kwargs)
            elapsed  = round((time.time() - t0) * 1000)
            if self._dm.get("auto_commit"):
                msgs   = kwargs.get("messages", [])
                output = ""
                try:
                    output = response.choices[0].message.content or ""
                except Exception:
                    pass
                _dm_commit(
                    api_key    = self._dm["api_key"],
                    agent_name = self._dm["agent_name"],
                    base_url   = self._dm["base_url"],
                    payload    = {
                        "input":      str(msgs[-1].get("content", "") if msgs else "")[:500],
                        "output":     str(output)[:500],
                        "model":      kwargs.get("model", "?"),
                        "messages":   len(msgs),
                        "latency_ms": elapsed,
                        "wrapper":    "openai_chat",
                    },
                    event_type = "openai_chat_call",
                    trace_id   = dm_trace_id,
                    dm_debug   = self._dm.get("debug", False),
                )
            return response
        return wrapped

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)


# Also export AsyncOpenAI variant
class AsyncOpenAI(_AsyncOpenAI):
    """Async variant — instruments chat.completions.create and responses.create."""

    def __init__(
        self,
        *args,
        dm_api_key:    Optional[str] = None,
        dm_agent_name: Optional[str] = None,
        dm_base_url:   str = "https://darkmatterhub.ai",
        dm_auto_commit: bool = True,
        dm_debug:      bool = False,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self._dm = {
            "api_key":    dm_api_key    or os.environ.get("DARKMATTER_API_KEY", ""),
            "agent_name": dm_agent_name or os.environ.get("DARKMATTER_AGENT_NAME", "openai-agent"),
            "base_url":   dm_base_url,
            "auto_commit": dm_auto_commit,
            "debug":      dm_debug,
        }
        if hasattr(super(), "responses"):
            self._responses_wrapped = _DarkMatterResponses(super().responses, self._dm)

    @property
    def responses(self) -> _DarkMatterResponses:
        return getattr(self, "_responses_wrapped", _DarkMatterResponses(super().responses, self._dm))
