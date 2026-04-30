"""
DarkMatter Google ADK Integration
=====================================
Automatic Context Passport commits for Google Agent Development Kit agents.
Subclass DarkMatterADKAgent instead of LlmAgent — zero other changes.

Install: pip install darkmatter-sdk google-adk
"""

from __future__ import annotations
import threading
from typing import Any, AsyncIterator, Optional

import darkmatter as dm


class DarkMatterADKAgent:
    """
    Drop-in subclass of google.adk.agents.LlmAgent.
    Commits a Context Passport automatically after each final response.

    Usage:
        from darkmatter.integrations.google_adk import DarkMatterADKAgent

        dm.configure(api_key="dm_sk_...", agent_id="dm_agent_...")
        agent = DarkMatterADKAgent(
            name        = "research_agent",
            model       = "gemini-2.0-flash",
            instruction = "You are a research assistant.",
            to_agent_id = "dm_agent_...",
            trace_id    = "trc_adk_001",
        )
        # Use agent exactly as you would LlmAgent
    """

    def __init__(
        self,
        *args,
        to_agent_id: str,
        trace_id:    Optional[str] = None,
        branch_key:  Optional[str] = None,
        async_commit: bool = True,
        **kwargs,
    ):
        try:
            from google.adk.agents import LlmAgent
            self.__class__.__bases__ = (LlmAgent,)
            super().__init__(*args, **kwargs)
        except ImportError:
            raise ImportError("pip install google-adk")

        self._dm_to_agent_id = to_agent_id
        self._dm_trace_id    = trace_id
        self._dm_branch_key  = branch_key
        self._dm_async       = async_commit
        self._dm_last_ctx_id: Optional[str] = None
        self._dm_lock = threading.Lock()

    async def _run_async_impl(self, ctx: Any) -> AsyncIterator[Any]:
        """Intercept ADK event stream. Commit after final response."""
        async for event in super()._run_async_impl(ctx):
            yield event

            try:
                if not getattr(event, 'is_final_response', lambda: False)():
                    continue
                content = getattr(event, 'content', None)
                if not content:
                    continue

                parts = getattr(content, 'parts', []) or []
                output = " ".join(
                    p.text for p in parts if hasattr(p, "text") and p.text
                )
                if not output:
                    continue

                # Extract input from context
                user_content = getattr(ctx, 'user_content', None)
                inp = str(user_content) if user_content else ""

                payload = {
                    "input":  inp,
                    "output": output,
                    "agent": {
                        "provider": "google_adk",
                        "model":    getattr(self, 'model', None),
                        "role":     getattr(self, 'name', None),
                    },
                }

                def _commit(p=payload):
                    with self._dm_lock:
                        r = dm.commit(
                            to_agent_id = self._dm_to_agent_id,
                            payload     = p,
                            parent_id   = self._dm_last_ctx_id,
                            trace_id    = self._dm_trace_id,
                            branch_key  = self._dm_branch_key,
                        )
                        self._dm_last_ctx_id = r.get("id")

                if self._dm_async:
                    threading.Thread(target=_commit, daemon=True).start()
                else:
                    _commit()

            except Exception as e:
                import warnings
                warnings.warn(f"DarkMatter ADK commit failed: {e}")

    @property
    def last_ctx_id(self) -> Optional[str]:
        return self._dm_last_ctx_id


class DarkMatterADKRunner:
    """
    Wraps google.adk.Runner to commit a Context Passport after each session turn.
    Use when you need multi-turn lineage across an ADK Runner session.

    Usage:
        from darkmatter.integrations.google_adk import DarkMatterADKRunner
        from google.adk import Runner

        runner = Runner(agent=my_agent, ...)
        dm_runner = DarkMatterADKRunner(
            runner      = runner,
            to_agent_id = "dm_agent_...",
            trace_id    = "trc_session_001",
        )
        async for event in dm_runner.run_async(user_id="u1", session_id="s1", new_message=msg):
            ...
    """

    def __init__(
        self,
        runner:      Any,
        to_agent_id: str,
        trace_id:    Optional[str] = None,
        branch_key:  Optional[str] = None,
    ):
        self._runner     = runner
        self.to_agent_id = to_agent_id
        self.trace_id    = trace_id
        self.branch_key  = branch_key
        self.last_ctx_id: Optional[str] = None

    async def run_async(
        self,
        user_id:     str,
        session_id:  str,
        new_message: Any,
    ) -> AsyncIterator[Any]:
        last_input  = str(new_message)
        last_output = ""

        async for event in self._runner.run_async(
            user_id=user_id, session_id=session_id, new_message=new_message
        ):
            yield event
            try:
                if getattr(event, 'is_final_response', lambda: False)():
                    content = getattr(event, 'content', None)
                    if content:
                        parts = getattr(content, 'parts', []) or []
                        last_output = " ".join(
                            p.text for p in parts if hasattr(p, "text") and p.text
                        )
            except Exception:
                pass

        if last_output:
            try:
                r = dm.commit(
                    to_agent_id = self.to_agent_id,
                    payload     = {"input": last_input, "output": last_output},
                    parent_id   = self.last_ctx_id,
                    trace_id    = self.trace_id,
                    branch_key  = self.branch_key,
                )
                self.last_ctx_id = r.get("id")
            except Exception as e:
                import warnings
                warnings.warn(f"DarkMatter ADK Runner commit failed: {e}")
