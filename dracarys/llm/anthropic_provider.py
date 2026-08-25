"""Anthropic implementation of the LLM provider.

Uses the messages API and asks for JSON-only output, which is then parsed and
validated by the caller. Requires ``anthropic`` and an API key; if either is
missing the platform simply uses the heuristic planner instead.
"""
from __future__ import annotations

from typing import Any

from dracarys.config import Settings, get_settings
from dracarys.llm.provider import LLMError, extract_json


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        if not self.settings.anthropic_api_key:
            raise LLMError("ANTHROPIC_API_KEY is not configured")
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise LLMError("anthropic package is not installed") from exc
        self._client = anthropic.AsyncAnthropic(api_key=self.settings.anthropic_api_key)

    async def complete_json(self, system: str, user: str) -> Any:
        try:
            msg = await self._client.messages.create(
                model=self.settings.llm_model,
                max_tokens=self.settings.llm_max_tokens,
                system=system + "\n\nRespond with JSON only. No prose, no code fences.",
                messages=[{"role": "user", "content": user}],
            )
        except Exception as exc:  # noqa: BLE001  # network/SDK errors
            raise LLMError(f"anthropic request failed: {exc}") from exc
        parts = [
            getattr(b, "text", "")
            for b in msg.content
            if getattr(b, "type", None) == "text"
        ]
        if not parts:
            raise LLMError("empty model response")
        return extract_json("".join(parts))
