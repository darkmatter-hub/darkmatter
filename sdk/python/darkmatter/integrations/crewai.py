"""
DarkMatter CrewAI Integration
==============================
Automatic Context Passport commits after every CrewAI task.
Zero changes to your existing crew — add DarkMatterObserver and go.

Install: pip install darkmatter-sdk crewai
"""

from __future__ import annotations
import threading
from typing import Any, Optional, TYPE_CHECKING

try:
    from crewai.utilities.events import (
        crewai_event_bus,
        TaskCompletedEvent,
        AgentActionEvent,
        CrewKickoffEvent,
        CrewFinishedEvent,
    )
    CREWAI_EVENTS_AVAILABLE = True
except ImportError:
    CREWAI_EVENTS_AVAILABLE = False

try:
    from crewai import Task, Agent
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

import darkmatter as dm


class DarkMatterObserver:
    """
    Attach to any CrewAI crew to automatically commit a Context Passport
    after each task completes. Builds the full lineage chain across tasks.

    Usage:
        from darkmatter.integrations.crewai import DarkMatterObserver

        dm.configure(api_key="dm_sk_...", agent_id="dm_agent_...")
        observer = DarkMatterObserver(to_agent_id="dm_agent_...", trace_id="trc_001")
        observer.attach()

        crew = Crew(agents=[...], tasks=[...])
        crew.kickoff()
        # Every task automatically committed. Chain built. Done.
    """

    def __init__(
        self,
        to_agent_id: str,
        trace_id: Optional[str] = None,
        branch_key: Optional[str] = None,
        async_commit: bool = True,
    ):
        self.to_agent_id = to_agent_id
        self.trace_id    = trace_id
        self.branch_key  = branch_key
        self.async_commit = async_commit
        self._last_ctx_id: Optional[str] = None
        self._lock = threading.Lock()

    def attach(self) -> "DarkMatterObserver":
        """Subscribe to CrewAI events. Call once before crew.kickoff()."""
        if not CREWAI_EVENTS_AVAILABLE:
            raise ImportError(
                "crewai events API not available. "
                "Install crewai >= 0.60.0: pip install 'crewai>=0.60.0'"
            )
        crewai_event_bus.on(TaskCompletedEvent, self._on_task_completed)
        return self

    def detach(self) -> None:
        """Unsubscribe from CrewAI events."""
        if CREWAI_EVENTS_AVAILABLE:
            crewai_event_bus.off(TaskCompletedEvent, self._on_task_completed)

    def _on_task_completed(self, source: Any, event: Any) -> None:
        """Fires after each task completes. Commits payload to DarkMatter."""
        try:
            task   = event.task
            output = event.output

            task_desc = getattr(task, 'description', str(task))
            agent     = getattr(task, 'agent', None)
            role      = getattr(agent, 'role', None) if agent else None
            model     = None
            if agent:
                llm = getattr(agent, 'llm', None)
                if llm:
                    model = getattr(llm, 'model_name', None) or getattr(llm, 'model', None)

            raw_output = (
                output.raw if hasattr(output, 'raw')
                else str(output)
            )

            payload = {
                'input':  task_desc,
                'output': raw_output,
                'agent':  {
                    'role':     role,
                    'model':    model,
                    'provider': 'crewai',
                },
            }

            def _commit():
                with self._lock:
                    result = dm.commit(
                        to_agent_id = self.to_agent_id,
                        payload     = payload,
                        parent_id   = self._last_ctx_id,
                        trace_id    = self.trace_id,
                        branch_key  = self.branch_key,
                        event_type  = 'commit',
                    )
                    self._last_ctx_id = result.get('id')

            if self.async_commit:
                threading.Thread(target=_commit, daemon=True).start()
            else:
                _commit()

        except Exception as e:
            # Never raise — don't break the crew
            import warnings
            warnings.warn(f"DarkMatter CrewAI commit failed: {e}")

    @property
    def last_ctx_id(self) -> Optional[str]:
        return self._last_ctx_id


def observe_crew(
    to_agent_id: str,
    trace_id: Optional[str] = None,
    branch_key: Optional[str] = None,
    async_commit: bool = True,
) -> DarkMatterObserver:
    """
    One-line helper. Returns an attached observer.

    Example:
        observer = dm_crewai.observe_crew(to_agent_id="dm_agent_...", trace_id="run_001")
        crew.kickoff()
    """
    return DarkMatterObserver(
        to_agent_id  = to_agent_id,
        trace_id     = trace_id,
        branch_key   = branch_key,
        async_commit = async_commit,
    ).attach()
