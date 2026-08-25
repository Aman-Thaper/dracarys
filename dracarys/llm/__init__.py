"""Provider-agnostic LLM integration.

The platform never couples to a single model vendor. Planning may be driven by an
LLM, but findings are ALWAYS validated deterministically — free-form model output
can never assert a vulnerability or bypass policy.
"""
from dracarys.llm.provider import LLMError, LLMProvider, MockProvider

__all__ = ["LLMProvider", "MockProvider", "LLMError"]
