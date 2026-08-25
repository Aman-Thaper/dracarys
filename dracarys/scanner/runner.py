"""Build and run a scan against a live URL, with the authorization/safety gate."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from dracarys.config import get_settings
from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.scanner import ScanConfig, Scanner
from dracarys.tools import HttpTool

LOOPBACK = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


@dataclass
class Authorization:
    ok: bool
    reason: str
    is_loopback: bool
    host: str
    port: int


def _is_loopback(host: str) -> bool:
    if host in LOOPBACK:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            import ipaddress
            if not ipaddress.ip_address(info[4][0]).is_loopback:
                return False
        return True
    except (socket.gaierror, ValueError):
        return False


def authorize(url: str, authorized: bool) -> Authorization:
    """Gate scanning of non-loopback targets behind explicit authorization."""
    p = urlparse(url)
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    if not host or p.scheme not in ("http", "https"):
        return Authorization(False, "target must be an http(s) URL", False, host, port)
    loop = _is_loopback(host)
    if loop or authorized:
        return Authorization(True, "authorized", loop, host, port)
    return Authorization(
        False,
        "Refusing to scan a non-loopback target without explicit authorization. "
        "Only scan systems you are authorized to test, then pass --yes-i-am-authorized "
        "(or set DRACARYS_AUTHORIZED=1).",
        loop, host, port,
    )


def build_scanner(
    url: str, *, config: ScanConfig, extra_hosts: list[str] | None = None,
    max_requests: int = 3000, timeout: float | None = None, allow_private_only: bool | None = None,
) -> tuple[Scanner, httpx.AsyncClient]:
    settings = get_settings()
    p = urlparse(url)
    host = (p.hostname or "").lower()
    port = p.port or (443 if p.scheme == "https" else 80)
    base = f"{p.scheme}://{p.netloc}"
    loop = _is_loopback(host)
    scope = Scope.create(
        [host, *(extra_hosts or [])], [port],
        allow_private_only=loop if allow_private_only is None else allow_private_only,
    )
    policy = PolicyEngine(
        scope, max_requests=max_requests, max_concurrency=settings.max_concurrency,
        timeout_seconds=timeout or settings.tool_timeout_seconds,
    )
    client = httpx.AsyncClient(base_url=base, follow_redirects=False)
    return Scanner(HttpTool(base, policy, client), base, config), client


async def run_scan(url: str, config: ScanConfig, **kw):
    scanner, client = build_scanner(url, config=config, **kw)
    try:
        return await scanner.scan()
    finally:
        await client.aclose()
