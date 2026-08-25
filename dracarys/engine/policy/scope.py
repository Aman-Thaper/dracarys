"""Scope validation — the network boundary of the platform.

A tool request is only allowed to reach a host/port that is both (a) on the
campaign's explicit allowlist and (b) an address that resolves to a loopback or
private range. Both conditions must hold; the second is defense-in-depth against
an allowlisted hostname that resolves somewhere public (DNS rebinding / typos).
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


@dataclass(frozen=True)
class Scope:
    """Immutable scope snapshot for a campaign."""

    hosts: frozenset[str]
    ports: frozenset[int]
    allow_private_only: bool = True

    @classmethod
    def create(cls, hosts, ports, allow_private_only: bool = True) -> Scope:
        return cls(
            hosts=frozenset(h.lower() for h in hosts),
            ports=frozenset(int(p) for p in ports),
            allow_private_only=allow_private_only,
        )

    def to_dict(self) -> dict:
        return {
            "hosts": sorted(self.hosts),
            "ports": sorted(self.ports),
            "allow_private_only": self.allow_private_only,
        }


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    resolved_ips: tuple[str, ...] = field(default_factory=tuple)

    def __bool__(self) -> bool:
        return self.allowed


@lru_cache(maxsize=256)
def _resolve(host: str) -> tuple[str, ...]:
    """Resolve a host to a tuple of IP strings (cached). Empty tuple on failure."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return ()
    ips = sorted({str(info[4][0]) for info in infos})
    return tuple(ips)


def _all_private_or_loopback(ips: tuple[str, ...]) -> bool:
    if not ips:
        return False
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if not (addr.is_loopback or addr.is_private or addr.is_link_local):
            return False
    return True


def validate_url(url: str, scope: Scope) -> ScopeDecision:
    """Return a ScopeDecision for whether ``url`` may be reached under ``scope``."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()

    if scheme not in ALLOWED_SCHEMES:
        return ScopeDecision(False, f"scheme '{scheme}' not permitted", scheme=scheme)

    if parsed.username or parsed.password:
        return ScopeDecision(False, "embedded credentials are not permitted")

    host = (parsed.hostname or "").lower()
    if not host:
        return ScopeDecision(False, "missing host")

    port = parsed.port
    if port is None:
        port = 443 if scheme == "https" else 80

    if host not in scope.hosts:
        return ScopeDecision(
            False, f"host '{host}' is not on the scope allowlist",
            host=host, port=port, scheme=scheme,
        )

    if port not in scope.ports:
        return ScopeDecision(
            False, f"port {port} is not on the scope allowlist",
            host=host, port=port, scheme=scheme,
        )

    resolved = _resolve(host)
    if scope.allow_private_only and not _all_private_or_loopback(resolved):
        return ScopeDecision(
            False,
            f"host '{host}' resolves outside private/loopback ranges: {resolved}",
            host=host, port=port, scheme=scheme, resolved_ips=resolved,
        )

    return ScopeDecision(
        True, "in scope", host=host, port=port, scheme=scheme, resolved_ips=resolved
    )
