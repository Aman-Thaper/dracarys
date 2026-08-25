"""Unit tests for the scope validator and policy engine (the safety boundary)."""
import pytest

from dracarys.engine.policy import PolicyEngine, PolicyError, Scope, validate_url


def test_scope_allows_localhost_on_allowed_port(make_scope):
    d = validate_url("http://127.0.0.1:8888/api/health", make_scope())
    assert d.allowed and d.host == "127.0.0.1" and d.port == 8888


@pytest.mark.parametrize(
    "url,reason_contains",
    [
        ("http://127.0.0.1:9999/", "port"),
        ("http://evil.com:8888/", "allowlist"),
        ("https://8.8.8.8:8888/", "allowlist"),
        ("file:///etc/passwd", "scheme"),
        ("gopher://127.0.0.1:8888/", "scheme"),
        ("http://user:pass@127.0.0.1:8888/", "credentials"),
        ("http://:8888/", "host"),
    ],
)
def test_scope_denies_out_of_bounds(make_scope, url, reason_contains):
    d = validate_url(url, make_scope())
    assert not d.allowed
    assert reason_contains in d.reason


def test_public_ip_blocked_even_if_allowlisted():
    # An allowlisted hostname that resolves to a public IP is still rejected.
    scope = Scope.create(["example.com"], [80])
    d = validate_url("http://example.com:80/", scope)
    assert not d.allowed
    assert "private" in d.reason or "allowlist" in d.reason


async def test_policy_budget_exhaustion(make_scope):
    eng = PolicyEngine(make_scope(), max_requests=2, max_concurrency=2, timeout_seconds=1)
    url = "http://127.0.0.1:8888/x"
    async with eng.guard(url):
        pass
    async with eng.guard(url):
        pass
    with pytest.raises(PolicyError, match="budget"):
        async with eng.guard(url):
            pass
    assert eng.requests_made == 2


async def test_policy_kill_switch(make_scope):
    eng = PolicyEngine(make_scope(), max_requests=10, max_concurrency=2, timeout_seconds=1)
    eng.kill("operator STOP")
    assert eng.killed
    with pytest.raises(PolicyError, match="killed"):
        async with eng.guard("http://127.0.0.1:8888/x"):
            pass


async def test_policy_blocks_out_of_scope(make_scope):
    eng = PolicyEngine(make_scope(), max_requests=10, max_concurrency=2, timeout_seconds=1)
    with pytest.raises(PolicyError, match="allowlist"):
        async with eng.guard("http://evil.com:8888/"):
            pass
    assert eng.requests_made == 0  # denied calls consume no budget
