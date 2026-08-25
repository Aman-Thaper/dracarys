"""LLM provider protocol and a deterministic mock for tests."""
from __future__ import annotations

import json
from typing import Any, Protocol, runtime_checkable


class LLMError(Exception):
    """Raised when a provider fails or returns unusable output."""


@runtime_checkable
class LLMProvider(Protocol):
    name: str

    async def complete_json(self, system: str, user: str) -> Any:
        """Return parsed JSON from the model, or raise LLMError."""
        ...


def extract_json(text: str) -> Any:
    """Best-effort extraction of the first JSON value in a text blob."""
    text = text.strip()
    if text.startswith("```"):
        # strip code fences
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    for opener, closer in (("[", "]"), ("{", "}")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise LLMError("model did not return valid JSON")


class MockProvider:
    """Returns a canned JSON response; used to test the LLM planner offline."""

    name = "mock"

    def __init__(self, response: Any) -> None:
        self._response = response

    async def complete_json(self, system: str, user: str) -> Any:
        return self._response
