"""The generic scanner must find real vulns and avoid false positives.

The fixture apps are intentionally unlike the DRACARYS BANK lab; passing these
demonstrates the detectors generalize rather than matching a known target.
"""
import httpx
import pytest

from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.scanner import ScanConfig, Scanner
from dracarys.tools import HttpTool
from tests.fixtures.vuln_apps import build_api_app, build_blog_app, build_safe_app

pytestmark = pytest.mark.integration


def _tool(app, base):
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)
    policy = PolicyEngine(Scope.create(["127.0.0.1"], [8888, 8889]),
                          max_requests=3000, max_concurrency=4, timeout_seconds=8)
    return HttpTool(base, policy, client), client


async def _scan(app, base, cfg):
    tool, client = _tool(app, base)
    try:
        return await Scanner(tool, base, cfg).scan()
    finally:
        await client.aclose()


async def test_blog_app_detected():
    res = await _scan(build_blog_app(), "http://127.0.0.1:8888",
                      ScanConfig(active=True, include_time_based=False))
    cats = {f.category.value for f in res.findings}
    assert {"sql_injection", "xss", "open_redirect", "exposed_resource",
            "sensitive_data", "security_misconfig"} <= cats
    sqli = next(f for f in res.findings if f.category.value == "sql_injection")
    assert sqli.param == "id" and sqli.cwe == "CWE-89"
    xss = next(f for f in res.findings if f.category.value == "xss")
    assert xss.param == "q" and all(e.exchange for e in xss.evidence)


async def test_api_app_detected():
    res = await _scan(build_api_app(), "http://127.0.0.1:8889",
                      ScanConfig(active=True, include_time_based=False,
                                 auth_headers={"Authorization": "Bearer tok-user1"},
                                 second_identity_headers={"Authorization": "Bearer tok-user2"},
                                 protected_urls=["http://127.0.0.1:8889/api/v2/notes/1001"]))
    cats = {f.category.value for f in res.findings}
    assert {"sql_injection", "sensitive_data", "idor", "info_disclosure"} <= cats
    sqli = next(f for f in res.findings if f.category.value == "sql_injection")
    assert sqli.param == "filter"  # boolean-based, discovered via OpenAPI import


async def test_safe_app_no_false_positives():
    res = await _scan(build_safe_app(), "http://127.0.0.1:8888",
                      ScanConfig(active=True, include_time_based=False))
    cats = {f.category.value for f in res.findings}
    # No serious active-class false positives on a hardened app.
    assert "sql_injection" not in cats
    assert "xss" not in cats
    assert "open_redirect" not in cats
    assert "idor" not in cats
    assert "exposed_resource" not in cats


async def test_passive_only_mode_skips_injection():
    res = await _scan(build_blog_app(), "http://127.0.0.1:8888", ScanConfig(active=False))
    cats = {f.category.value for f in res.findings}
    assert "sql_injection" not in cats and "xss" not in cats
    # passive checks still fire
    assert "security_misconfig" in cats


async def test_scan_api_rejects_unauthorized_external(api_client):
    r = await api_client.post("/api/scan", json={"url": "https://example.com/", "authorized": False})
    assert r.status_code == 422
    assert "authoriz" in r.json()["error"].lower()


async def test_scan_api_rejects_bad_scheme(api_client):
    r = await api_client.post("/api/scan", json={"url": "ftp://x/", "authorized": True})
    assert r.status_code == 422
