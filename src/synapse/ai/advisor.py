"""Pluggable AI advisor for pentest triage and reasoning.

The deterministic decision engine lives in ``synapse.assessment`` and is the
single source of recommendations (TUI triage board, stats banner, CLI
``next``). This module is strictly an optional LLM advisory layer: it never
runs offline decisions and requires an explicit API key.
"""

from __future__ import annotations

import os
from typing import Optional

import httpx


class AIAdvisor:
    """Optional LLM advisory hook with no deterministic fallback logic."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        provider: str = "auto",
        api_base: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.api_key = (
            api_key
            or os.environ.get("SYNAPSE_AI_API_KEY")
            or os.environ.get("OPENCODE_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("ANTHROPIC_API_KEY")
        )
        self.provider = provider
        self.api_base = api_base or os.environ.get("SYNAPSE_AI_BASE") or "https://api.openai.com/v1"
        self.model = model or os.environ.get("SYNAPSE_AI_MODEL") or "gpt-4o-mini"

    @property
    def is_ai_available(self) -> bool:
        return bool(self.api_key)

    async def query_llm_analysis(self, prompt: str, system_prompt: Optional[str] = None) -> Optional[str]:
        """Queries the configured LLM endpoint asynchronously if available."""
        if not self.is_ai_available:
            return None

        sys_msg = system_prompt or (
            "You are Synapse, an expert offensive security reasoning engine assisting with authorized penetration tests, "
            "eJPTv2 labs, and CTFs. Provide concise, high-signal, prioritized attack hypotheses and exact commands."
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": sys_msg},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.post(
                    f"{self.api_base.rstrip('/')}/chat/completions",
                    headers=headers,
                    json=payload,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception:
            pass

        return None
