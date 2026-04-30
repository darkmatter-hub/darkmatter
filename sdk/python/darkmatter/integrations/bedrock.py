"""
DarkMatter AWS Bedrock Integration
=====================================
Automatic Context Passport commits for Bedrock model invocations.
Drop-in wrapper for boto3 bedrock-runtime — one line to wrap.

Install: pip install darkmatter-sdk boto3
"""

from __future__ import annotations
import json
import threading
from typing import Any, Optional

import darkmatter as dm


class DarkMatterBedrockClient:
    """
    Drop-in wrapper for boto3 bedrock-runtime client.
    Commits a Context Passport automatically after every invoke_model() call.

    Usage:
        from darkmatter.integrations.bedrock import DarkMatterBedrockClient

        dm.configure(api_key="dm_sk_...", agent_id="dm_agent_...")
        bedrock = DarkMatterBedrockClient(
            region      = "us-east-1",
            to_agent_id = "dm_agent_...",
            trace_id    = "trc_bedrock_001",
        )
        result = bedrock.invoke_model(
            model_id = "anthropic.claude-opus-4-6-v1:0",
            prompt   = "Analyze this contract for risk clauses",
        )
        print(bedrock.last_ctx_id)  # ctx_...
    """

    def __init__(
        self,
        region: str,
        to_agent_id: str,
        trace_id:    Optional[str] = None,
        branch_key:  Optional[str] = None,
        role:        Optional[str] = None,
        async_commit: bool = True,
        **boto3_kwargs,
    ):
        try:
            import boto3
        except ImportError:
            raise ImportError("pip install boto3")

        self._client     = boto3.client("bedrock-runtime", region_name=region, **boto3_kwargs)
        self.to_agent_id = to_agent_id
        self.trace_id    = trace_id
        self.branch_key  = branch_key
        self.role        = role
        self.async_commit = async_commit
        self.last_ctx_id: Optional[str] = None
        self._lock = threading.Lock()

    def invoke_model(
        self,
        model_id: str,
        prompt:   str,
        max_tokens: int = 1024,
        system:     Optional[str] = None,
        **kwargs,
    ) -> dict:
        """
        Invoke a Bedrock model and auto-commit a Context Passport.
        Supports Claude, Titan, Llama, Mistral, and any Bedrock-hosted model.
        """
        # Build the request body — handles Claude messages format + legacy format
        if "anthropic.claude" in model_id:
            messages = [{"role": "user", "content": prompt}]
            body: dict = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": max_tokens,
                "messages": messages,
            }
            if system:
                body["system"] = system
        else:
            # Generic / Titan / Llama format
            body = {"inputText": prompt, "textGenerationConfig": {"maxTokenCount": max_tokens}}
            body.update(kwargs.get("extra_body", {}))

        response = self._client.invoke_model(
            modelId     = model_id,
            body        = json.dumps(body),
            contentType = "application/json",
            accept      = "application/json",
        )
        result = json.loads(response["body"].read())

        # Extract output across model families
        output = (
            result.get("content", [{}])[0].get("text")          # Claude messages
            or result.get("completion")                           # Claude legacy
            or result.get("outputs", [{}])[0].get("text")        # Titan
            or result.get("generation")                           # Llama
            or result.get("choices", [{}])[0].get("text", "")    # Mistral
            or str(result)
        )

        payload = {
            "input":  prompt,
            "output": output,
            "model":  model_id,
            "agent":  {
                "provider": "aws_bedrock",
                "model":    model_id,
                "role":     self.role,
            },
        }
        if system:
            payload["system"] = system

        def _commit():
            with self._lock:
                r = dm.commit(
                    to_agent_id = self.to_agent_id,
                    payload     = payload,
                    parent_id   = self.last_ctx_id,
                    trace_id    = self.trace_id,
                    branch_key  = self.branch_key,
                    event_type  = "commit",
                )
                self.last_ctx_id = r.get("id")

        if self.async_commit:
            threading.Thread(target=_commit, daemon=True).start()
        else:
            _commit()

        return result

    def invoke_agent(
        self,
        agent_id:    str,
        agent_alias: str,
        session_id:  str,
        prompt:      str,
    ) -> str:
        """
        Invoke a Bedrock Agent (not a raw model) and auto-commit.
        Returns the agent's final response text.
        """
        try:
            import boto3
            ba_client = boto3.client("bedrock-agent-runtime", region_name=self._client.meta.region_name)
        except ImportError:
            raise ImportError("pip install boto3")

        response = ba_client.invoke_agent(
            agentId      = agent_id,
            agentAliasId = agent_alias,
            sessionId    = session_id,
            inputText    = prompt,
        )
        output_parts = []
        for event in response.get("completion", []):
            chunk = event.get("chunk", {})
            if "bytes" in chunk:
                output_parts.append(chunk["bytes"].decode("utf-8"))
        output = "".join(output_parts)

        payload = {
            "input":  prompt,
            "output": output,
            "agent":  {
                "provider":    "aws_bedrock_agent",
                "agent_id":    agent_id,
                "agent_alias": agent_alias,
                "role":        self.role,
            },
        }

        def _commit():
            with self._lock:
                r = dm.commit(
                    to_agent_id = self.to_agent_id,
                    payload     = payload,
                    parent_id   = self.last_ctx_id,
                    trace_id    = self.trace_id,
                    branch_key  = self.branch_key,
                )
                self.last_ctx_id = r.get("id")

        if self.async_commit:
            threading.Thread(target=_commit, daemon=True).start()
        else:
            _commit()

        return output
