"""The lab must be genuinely vulnerable when unpatched and fixed when patched.

These tests protect the objective ground truth the whole platform is scored on.
"""
import httpx

from lab.app import create_lab_app
from lab.ground_truth import (
    CANARY_TOKEN,
    GROUND_TRUTH,
    LEAKED_PASSWORD,
    LEAKED_USER,
    patch_all,
)

UNION = "zzz%' UNION SELECT secret_name, secret_value, 'secret' FROM secrets -- "


async def _client(patches):
    app = create_lab_app(set(patches))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://lab")


async def _login(c, user=LEAKED_USER, pw=LEAKED_PASSWORD):
    r = await c.post("/api/login", json={"username": user, "password": pw})
    if r.status_code != 200:
        return None
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


async def test_info_disclosure_leaks_credential_when_vulnerable():
    c = await _client(set())
    r = await c.get("/api/system/status", params={"verbose": "1"})
    assert r.status_code == 200 and LEAKED_PASSWORD in r.text
    await c.aclose()


async def test_info_disclosure_fixed_when_patched():
    c = await _client({"LAB-INFO-001"})
    r = await c.get("/api/system/status", params={"verbose": "1"})
    assert LEAKED_PASSWORD not in r.text
    await c.aclose()


async def test_broken_auth_login_works_then_disabled():
    c = await _client(set())
    assert await _login(c) is not None
    await c.aclose()
    c2 = await _client({"LAB-AUTH-001"})
    assert await _login(c2) is None
    await c2.aclose()


async def test_idor_reaches_canary_then_blocked():
    c = await _client(set())
    h = await _login(c)
    r = await c.get("/api/accounts/9001", headers=h)
    assert r.status_code == 200 and CANARY_TOKEN in r.text
    await c.aclose()
    c2 = await _client({"LAB-IDOR-001"})
    h2 = await _login(c2)
    r2 = await c2.get("/api/accounts/9001", headers=h2)
    assert r2.status_code == 403 and CANARY_TOKEN not in r2.text
    await c2.aclose()


async def test_sqli_exfiltrates_canary_then_parameterized():
    c = await _client(set())
    h = await _login(c)
    ctrl = await c.get("/api/accounts/search", params={"q": "Alice"}, headers=h)
    inj = await c.get("/api/accounts/search", params={"q": UNION}, headers=h)
    assert CANARY_TOKEN not in ctrl.text and CANARY_TOKEN in inj.text
    await c.aclose()
    c2 = await _client({"LAB-SQL-001"})
    h2 = await _login(c2)
    inj2 = await c2.get("/api/accounts/search", params={"q": UNION}, headers=h2)
    assert CANARY_TOKEN not in inj2.text
    await c2.aclose()


async def test_misconfig_header_privesc_then_blocked():
    c = await _client(set())
    h = await _login(c)
    no_h = await c.get("/api/admin/users", headers=h)
    with_h = await c.get("/api/admin/users", headers={**h, "X-Account-Role": "admin"})
    assert no_h.status_code == 403 and with_h.status_code == 200
    await c.aclose()
    c2 = await _client({"LAB-MISCONFIG-001"})
    h2 = await _login(c2)
    with_h2 = await c2.get("/api/admin/users", headers={**h2, "X-Account-Role": "admin"})
    assert with_h2.status_code == 403
    await c2.aclose()


def test_ground_truth_catalogue_complete():
    assert set(GROUND_TRUTH) == {
        "LAB-INFO-001", "LAB-AUTH-001", "LAB-IDOR-001",
        "LAB-SQL-001", "LAB-MISCONFIG-001",
    }
    assert len(patch_all()) == 5
