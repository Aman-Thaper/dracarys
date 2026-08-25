"""Integration tests for the campaign lifecycle over the API."""
import asyncio

import pytest

pytestmark = pytest.mark.integration


async def _lab_target(api_client):
    targets = (await api_client.get("/api/targets")).json()
    return next(t for t in targets if t["is_lab"])


async def _run_to_complete(api_client, cid, timeout=30.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        camp = (await api_client.get(f"/api/campaigns/{cid}")).json()
        if camp["state"] in ("COMPLETE", "FAILED", "CANCELLED"):
            return camp
        await asyncio.sleep(0.05)
    raise AssertionError(f"campaign did not finish; last state {camp['state']}")


async def test_campaign_create_and_run(api_client):
    lab = await _lab_target(api_client)
    created = await api_client.post("/api/campaigns", json={"target_id": lab["id"], "name": "it"})
    assert created.status_code == 201
    cid = created.json()["id"]
    assert created.json()["state"] == "CREATED"

    started = await api_client.post(f"/api/campaigns/{cid}/start")
    assert started.status_code == 200

    camp = await _run_to_complete(api_client, cid)
    assert camp["state"] == "COMPLETE"
    assert camp["progress"]["target_compromised"] is True

    summary = (await api_client.get(f"/api/campaigns/{cid}/summary")).json()
    assert summary["counts"]["findings"] == 5
    assert summary["fixes_verified"] == 5
    assert summary["severity_breakdown"]["critical"] == 2


async def test_campaign_subresources(api_client):
    lab = await _lab_target(api_client)
    cid = (await api_client.post("/api/campaigns", json={"target_id": lab["id"]})).json()["id"]
    await api_client.post(f"/api/campaigns/{cid}/start")
    await _run_to_complete(api_client, cid)

    for path, minimum in [
        ("observations", 5), ("hypotheses", 5), ("findings", 5),
        ("test-runs", 5), ("evidence", 5), ("attack-paths", 2),
        ("remediations", 5), ("retests", 5), ("audit", 5),
    ]:
        rows = (await api_client.get(f"/api/campaigns/{cid}/{path}")).json()
        assert len(rows) >= minimum, f"{path}: {len(rows)} < {minimum}"

    graph = (await api_client.get(f"/api/campaigns/{cid}/graph")).json()
    assert len(graph["nodes"]) >= 8 and len(graph["edges"]) >= 8
    # every finding cites at least one evidence record
    findings = (await api_client.get(f"/api/campaigns/{cid}/findings")).json()
    assert all(f["evidence_refs"] for f in findings)


async def test_stop_before_start_cancels(api_client):
    lab = await _lab_target(api_client)
    cid = (await api_client.post("/api/campaigns", json={"target_id": lab["id"]})).json()["id"]
    stop = await api_client.post(f"/api/campaigns/{cid}/stop")
    assert stop.status_code == 200
    await api_client.post(f"/api/campaigns/{cid}/start")
    camp = await _run_to_complete(api_client, cid)
    assert camp["state"] == "CANCELLED"


async def test_cannot_start_twice(api_client):
    lab = await _lab_target(api_client)
    cid = (await api_client.post("/api/campaigns", json={"target_id": lab["id"]})).json()["id"]
    await api_client.post(f"/api/campaigns/{cid}/start")
    await _run_to_complete(api_client, cid)
    again = await api_client.post(f"/api/campaigns/{cid}/start")
    assert again.status_code == 409
