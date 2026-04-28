"""
darkmatter.integrations.langgraph
==================================
Native DarkMatter integration for LangGraph agents.

Usage
-----
from darkmatter.integrations.langgraph import DarkMatterTracer

# Attach to any LangGraph app
tracer = DarkMatterTracer(
    api_key="dm_sk_...",
    agent_name="my-langgraph-agent",  # optional
)

# Option A: wrap the compiled app
result = tracer.invoke(app, {"messages": [...]})

# Option B: use as a LangGraph callback
app.invoke(input, config=tracer.config())

# Option C: decorate individual nodes
@tracer.node("my_node")
def my_node(state):
    ...
    return state
"""

from __future__ import annotations

import time
import hashlib
import json
import os
import threading
from typing import Any, Dict, Optional, Callable


class DarkMatterTracer:
    """
    Integrates DarkMatter record-keeping into LangGraph agent execution.

    Each node execution is committed as a child record. The full graph
    run is committed as a parent record with a trace_id linking all steps.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        agent_name: Optional[str] = None,
        base_url: str = "https://darkmatterhub.ai",
        completeness_claim: bool = False,
        dm_auto_commit: bool = True,
        dm_debug: bool = False,
    ):
        self.api_key    = api_key or os.environ.get("DARKMATTER_API_KEY", "")
        self.agent_name = agent_name or os.environ.get("DARKMATTER_AGENT_NAME", "langgraph-agent")
        self.base_url   = base_url.rstrip("/")
        self.completeness_claim = completeness_claim
        self.auto_commit = dm_auto_commit
        self.debug       = dm_debug
        self._lock       = threading.Lock()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _commit(
        self,
        payload: Dict[str, Any],
        trace_id: Optional[str] = None,
        parent_id: Optional[str] = None,
        event_type: str = "langgraph_node",
    ) -> Dict[str, Any]:
        """POST a commit to DarkMatter. Returns the receipt."""
        if not self.api_key:
            if self.debug:
                print("[DarkMatter] No API key — skipping commit")
            return {}
        try:
            import urllib.request
            body = json.dumps({
                "toAgentId": self.agent_name,
                "payload":   payload,
                "eventType": event_type,
                "traceId":   trace_id,
                "parentId":  parent_id,
                "completeness_claim": self.completeness_claim,
                "agent": {
                    "name":     self.agent_name,
                    "provider": "langgraph",
                    "wrapper":  "darkmatter-langgraph",
                },
            }).encode()
            req = urllib.request.Request(
                f"{self.base_url}/api/commit",
                data=body,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type":  "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as r:
                receipt = json.loads(r.read())
                if self.debug:
                    print(f"[DarkMatter] committed {event_type} → {receipt.get('ctxId','?')}")
                return receipt
        except Exception as e:
            if self.debug:
                print(f"[DarkMatter] commit error: {e}")
            return {}

    def _make_trace_id(self) -> str:
        import secrets
        return "dm_trace_" + secrets.token_hex(8)

    # ── Public API ────────────────────────────────────────────────────────────

    def invoke(self, app: Any, input_state: Any, config: Optional[Dict] = None) -> Any:
        """
        Run a LangGraph app and record the full execution.

        Parameters
        ----------
        app         : compiled LangGraph StateGraph (.compile() result)
        input_state : initial state dict passed to app.invoke()
        config      : optional LangGraph config dict

        Returns
        -------
        The final state returned by app.invoke()
        """
        trace_id  = self._make_trace_id()
        t_start   = time.time()

        if self.debug:
            print(f"[DarkMatter] starting trace {trace_id}")

        # Run the graph
        result = app.invoke(input_state, config=config or {})

        elapsed = round((time.time() - t_start) * 1000)

        if self.auto_commit:
            # Summarise input/output — avoid leaking huge state objects
            input_summary  = self._summarise(input_state)
            output_summary = self._summarise(result)
            self._commit(
                payload={
                    "input":       input_summary,
                    "output":      output_summary,
                    "latency_ms":  elapsed,
                    "wrapper":     "langgraph",
                    "event":       "graph_run",
                },
                trace_id=trace_id,
                event_type="langgraph_graph",
            )

        return result

    def node(self, node_name: str) -> Callable:
        """
        Decorator that wraps a LangGraph node function and commits each
        invocation as a child record.

        Usage::

            @tracer.node("classify")
            def classify(state):
                ...
                return state
        """
        def decorator(fn: Callable) -> Callable:
            def wrapper(state: Any, *args, **kwargs) -> Any:
                t0     = time.time()
                result = fn(state, *args, **kwargs)
                ms     = round((time.time() - t0) * 1000)
                if self.auto_commit:
                    self._commit(
                        payload={
                            "node":       node_name,
                            "input":      self._summarise(state),
                            "output":     self._summarise(result),
                            "latency_ms": ms,
                            "wrapper":    "langgraph",
                        },
                        event_type="langgraph_node",
                    )
                return result
            wrapper.__name__ = fn.__name__
            return wrapper
        return decorator

    def config(self, trace_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Returns a LangGraph config dict with callbacks wired to DarkMatter.
        Pass this to app.invoke(input, config=tracer.config()).

        Note: requires LangChain callbacks to be installed.
        """
        try:
            from langchain_core.callbacks import BaseCallbackHandler

            class _DMCallback(BaseCallbackHandler):
                def __init__(self_, tracer_: "DarkMatterTracer", trace_id_: str):
                    self_._t     = tracer_
                    self_._tid   = trace_id_

                def on_llm_start(self_, serialized, prompts, **kw):
                    self_._t._commit(
                        payload={"event": "llm_start", "model": serialized.get("name","?"), "prompts": prompts[:1]},
                        trace_id=self_._tid, event_type="langgraph_llm",
                    )

                def on_llm_end(self_, response, **kw):
                    text = ""
                    try: text = response.generations[0][0].text[:300]
                    except: pass
                    self_._t._commit(
                        payload={"event": "llm_end", "output": text},
                        trace_id=self_._tid, event_type="langgraph_llm",
                    )

            tid = trace_id or self._make_trace_id()
            return {"callbacks": [_DMCallback(self, tid)]}
        except ImportError:
            if self.debug:
                print("[DarkMatter] langchain_core not installed — config() returns empty dict")
            return {}

    def _summarise(self, state: Any, max_chars: int = 500) -> Any:
        """Safely summarise a state object for the payload."""
        try:
            if isinstance(state, dict):
                # Keep messages short
                out = {}
                for k, v in state.items():
                    if k == "messages" and isinstance(v, list):
                        out[k] = [str(m)[:200] for m in v[-3:]]
                    else:
                        out[k] = str(v)[:200] if not isinstance(v, (int, float, bool)) else v
                return out
            return str(state)[:max_chars]
        except Exception:
            return "<unserializable>"
