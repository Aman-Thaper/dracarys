"""HTTP tool — the primary offensive capability, bounded by the PolicyEngine.

The tool cannot reach anything the policy engine does not authorize, applies a
hard timeout, and captures a complete request/response exchange for evidence.
An httpx client is injected so tests can drive it in-process against an ASGI app
while still exercising the full policy path.

Two entry points:
  * ``execute(spec)``      — path-relative to ``base_url`` (used by lab modules).
  * ``send(method, url)``  — absolute URL within scope (used by the scanner/crawler).
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urljoin

import httpx

from dracarys.engine.policy import PolicyEngine, PolicyError
from dracarys.logging import get_logger
from dracarys.tools.base import (
    MAX_CAPTURE_BYTES,
    HttpExchange,
    HttpRequestSpec,
    ToolStatus,
    sha256_hex,
)

log = get_logger("tools.http")


class HttpTool:
    name = "http"

    def __init__(
        self,
        base_url: str,
        policy: PolicyEngine,
        client: httpx.AsyncClient,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.policy = policy
        self.client = client

    def _full_url(self, path: str) -> str:
        return urljoin(self.base_url + "/", path.lstrip("/"))

    async def execute(self, spec: HttpRequestSpec) -> HttpExchange:
        return await self._perform(
            spec.method, self._full_url(spec.path), params=spec.query or None,
            headers=spec.headers or None, json=spec.json_body, note=spec.note,
        )

    async def send(
        self,
        method: str,
        url: str,
        *,
        params: dict | None = None,
        headers: dict | None = None,
        data: Any | None = None,
        json: Any | None = None,
        note: str = "",
    ) -> HttpExchange:
        """Request an absolute URL (scope-checked). Used by the generic scanner."""
        return await self._perform(
            method, url, params=params, headers=headers, data=data, json=json, note=note,
        )

    async def _perform(
        self, method: str, url: str, *, params=None, headers=None,
        data=None, json=None, note="",
    ) -> HttpExchange:
        request_meta = {
            "method": method, "url": url, "query": params or {},
            "headers": headers or {}, "json_body": json, "note": note,
        }
        started = time.perf_counter()
        try:
            async with self.policy.guard(url) as decision:
                try:
                    resp = await self.client.request(
                        method, url, params=params or None, headers=headers or None,
                        data=data, json=json, timeout=self.policy.timeout_seconds,
                        follow_redirects=False,
                    )
                except httpx.HTTPError as exc:
                    elapsed = int((time.perf_counter() - started) * 1000)
                    log.warning("http_error", url=url, error=str(exc))
                    return HttpExchange(
                        status=ToolStatus.ERROR, policy_reason=decision.reason,
                        request=request_meta, elapsed_ms=elapsed, error=str(exc),
                    )
                elapsed = int((time.perf_counter() - started) * 1000)
                body = resp.text[:MAX_CAPTURE_BYTES]
                return HttpExchange(
                    status=ToolStatus.OK, policy_reason=decision.reason,
                    request=request_meta,
                    response={
                        "status_code": resp.status_code,
                        "headers": dict(resp.headers),
                        "content_length": len(resp.content),
                    },
                    body_text=body, sha256=sha256_hex(body), elapsed_ms=elapsed,
                )
        except PolicyError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            log.warning("blocked_by_policy", url=url, reason=str(exc))
            return HttpExchange(
                status=ToolStatus.BLOCKED_BY_POLICY, policy_reason=str(exc),
                request=request_meta, elapsed_ms=elapsed, error=str(exc),
            )
