"""Integration test for the pause -> resume control flow (deterministic).

Pausing before the first phase runs makes the pause point deterministic; resume
then drives the campaign to completion.
"""
import asyncio

import pytest

pytestmark = pytest.mark.integration


async def _lab_target(api_client):
    targets = (await api_client.get("/api/targets")).json()
    return next(t for t in targets if t["is_lab"])


async def _wait_state(api_client, cid, states, timeout=30.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        camp = (await api_client.get(f"/api/campaigns/{cid}")).json()
        if camp["state"] in states:
            return camp
        await asyncio.sleep(0.05)
    raise AssertionError(f"never reached {states}; last {camp['state']}")


async def test_pause_then_resume_completes(api_client):
    lab = await _lab_target(api_client)
    cid = (await api_client.post("/api/campaigns", json={"target_id": lab["id"]})).json()["id"]

    # Request a pause before starting; the dispatcher will pause at the first gate.
    await api_client.post(f"/api/campaigns/{cid}/pause")
    await api_client.post(f"/api/campaigns/{cid}/start")
    paused = await _wait_state(api_client, cid, {"PAUSED"})
    assert paused["progress"].get("resume_from") == "CREATED"

    resumed = await api_client.post(f"/api/campaigns/{cid}/resume")
    assert resumed.status_code == 200
    done = await _wait_state(api_client, cid, {"COMPLETE"})
    findings = (await api_client.get(f"/api/campaigns/{cid}/findings")).json()
    assert done["state"] == "COMPLETE" and len(findings) == 5


async def test_resume_rejected_when_not_paused(api_client):
    lab = await _lab_target(api_client)
    cid = (await api_client.post("/api/campaigns", json={"target_id": lab["id"]})).json()["id"]
    r = await api_client.post(f"/api/campaigns/{cid}/resume")
    assert r.status_code == 409
