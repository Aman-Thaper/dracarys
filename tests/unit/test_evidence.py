"""Unit tests for evidence capture, hashing, and secret redaction."""
from dracarys.engine.evidence import EvidenceStore
from dracarys.tools.base import HttpExchange, ToolStatus, sha256_hex


def test_sha256_is_stable():
    assert sha256_hex("hello") == sha256_hex("hello")
    assert sha256_hex("a") != sha256_hex("b")


def test_evidence_payload_redacts_authorization():
    ex = HttpExchange(
        status=ToolStatus.OK,
        request={"method": "GET", "url": "http://127.0.0.1:8888/api/me",
                 "headers": {"Authorization": "Bearer tok_secret", "Accept": "application/json"}},
        response={"status_code": 200},
        body_text='{"ok": true}',
        sha256=sha256_hex('{"ok": true}'),
    )
    payload = ex.evidence_payload()
    assert payload["request"]["headers"]["Authorization"] == "Bearer ***redacted***"
    assert payload["request"]["headers"]["Accept"] == "application/json"


def test_contains_matches_body():
    ex = HttpExchange(status=ToolStatus.OK, body_text="the canary is HERE")
    assert ex.contains("canary")
    assert not ex.contains("absent")


async def test_evidence_store_persists_with_hash(db):
    async with db.session_factory() as s:
        # minimal campaign row for FK
        from dracarys.db.models import Campaign, Target
        t = Target(name="t", base_url="http://127.0.0.1:8888")
        s.add(t)
        await s.flush()
        c = Campaign(target_id=t.id)
        s.add(c)
        await s.flush()
        ex = HttpExchange(status=ToolStatus.OK, body_text="proof",
                          sha256=sha256_hex("proof"), response={"status_code": 200})
        store = EvidenceStore(s, c.id)
        ev = await store.record_exchange(ex, summary="test evidence")
        assert ev.sha256 == sha256_hex("proof")
        assert ev.id.startswith("evd_")
        assert ev.content["body_preview"] == "proof"
