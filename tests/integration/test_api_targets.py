"""Integration tests for target endpoints and scope enforcement."""
import pytest

pytestmark = pytest.mark.integration


async def test_health(api_client):
    r = await api_client.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["service"] == "dracarys"


async def test_lab_target_autoregistered(api_client):
    r = await api_client.get("/api/targets")
    assert r.status_code == 200
    targets = r.json()
    assert any(t["is_lab"] for t in targets)
    assert any(t["base_url"].endswith(":8888") for t in targets)


async def test_validate_endpoint_allows_and_denies(api_client):
    ok = await api_client.post("/api/targets/validate", json={"base_url": "http://127.0.0.1:8888/"})
    assert ok.json()["allowed"] is True
    bad = await api_client.post("/api/targets/validate", json={"base_url": "http://attacker.example:8888/"})
    body = bad.json()
    assert body["allowed"] is False and "allowlist" in body["reason"]


async def test_create_target_rejects_out_of_scope(api_client):
    r = await api_client.post("/api/targets", json={
        "name": "evil", "base_url": "http://8.8.8.8:53/", "is_lab": False,
    })
    assert r.status_code == 422
    assert "scope" in r.json()["error"]


async def test_create_target_in_scope(api_client):
    r = await api_client.post("/api/targets", json={
        "name": "local", "base_url": "http://127.0.0.1:8889/",
        "allowed_hosts": ["127.0.0.1"], "allowed_ports": [8889],
    })
    assert r.status_code == 201
    assert r.json()["validated"] is True


async def test_metrics_endpoint(api_client):
    r = await api_client.get("/api/metrics")
    assert r.status_code == 200
    body = r.json()
    assert "campaigns_by_state" in body
    assert "findings_by_severity" in body
    assert "fix_verification_rate" in body
