"""Tool request/result contracts.

Typed, validated schemas the planner (LLM or heuristic) fills in. Malformed tool
requests are rejected by Pydantic before anything touches the network.
"""
from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator

SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key"}
MAX_CAPTURE_BYTES = 65536


class ToolStatus(str, Enum):
    OK = "ok"                    # request completed (says nothing about vuln)
    ERROR = "error"              # transport/timeout error
    BLOCKED_BY_POLICY = "blocked_by_policy"


class HttpRequestSpec(BaseModel):
    """A single bounded HTTP action, relative to a target base URL."""

    method: str = Field(default="GET")
    path: str = Field(default="/")
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: Any | None = Field(default=None)
    note: str = Field(default="", description="Why the agent is making this request")

    @field_validator("method")
    @classmethod
    def _method_ok(cls, v: str) -> str:
        v = v.upper()
        if v not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            raise ValueError(f"unsupported HTTP method: {v}")
        return v

    @field_validator("path")
    @classmethod
    def _path_ok(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError("path must be absolute (start with '/')")
        return v


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            # keep a short non-secret prefix for readability
            prefix = v.split(" ")[0] if " " in v else ""
            out[k] = f"{prefix} ***redacted***".strip()
        else:
            out[k] = v
    return out


class HttpExchange(BaseModel):
    """Captured request/response, suitable for turning into Evidence."""

    status: ToolStatus
    policy_reason: str = ""
    request: dict[str, Any] = Field(default_factory=dict)
    response: dict[str, Any] = Field(default_factory=dict)
    body_text: str = ""            # up to MAX_CAPTURE_BYTES, for validators to match
    sha256: str = ""
    elapsed_ms: int = 0
    error: str | None = None

    @property
    def status_code(self) -> int | None:
        return self.response.get("status_code")

    def contains(self, needle: str) -> bool:
        return needle in self.body_text

    def evidence_payload(self) -> dict[str, Any]:
        """Redacted, persistable representation for the evidence store."""
        req = dict(self.request)
        if "headers" in req:
            req["headers"] = _redact_headers(req["headers"])
        preview = self.body_text[:4000]
        return {
            "request": req,
            "response": self.response,
            "body_preview": preview,
            "body_truncated": len(self.body_text) > len(preview),
        }


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()
