"""Typed tool layer. The agent selects tools; tools perform bounded operations.

The LLM never gets a shell. It emits typed tool requests that are validated,
scope-checked, executed, and captured as evidence.
"""
from dracarys.tools.base import HttpExchange, HttpRequestSpec, ToolStatus
from dracarys.tools.http_tool import HttpTool

__all__ = ["HttpRequestSpec", "HttpExchange", "ToolStatus", "HttpTool"]
