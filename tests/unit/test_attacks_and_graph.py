"""Unit tests for attack-module determinism and attack-graph chain discovery."""
from dracarys.agents.attacks import modules_in_order
from dracarys.agents.context import AttackContext
from dracarys.db.models import Finding
from dracarys.domain.enums import Severity, TestOutcome, VulnCategory
from dracarys.engine.graph import build_graph, discover_attack_paths


async def _run_chain(lab_factory, patches=frozenset()):
    tool, _ = lab_factory(patches=patches)
    ctx = AttackContext(canary_token="DRACARYS_CANARY{v4ult-r3c0v3ry-7Q2X-9F1B}")
    outcomes = {}
    for m in modules_in_order():
        out = await m.run(tool, ctx)
        ctx.merge(out.extracted)
        outcomes[m.id] = out
    return outcomes, ctx


async def test_full_chain_confirms_all_modules(lab_factory):
    outcomes, ctx = await _run_chain(lab_factory)
    for mid, out in outcomes.items():
        assert out.outcome == TestOutcome.CONFIRMED, f"{mid} not confirmed"
    assert ctx.reached_canary
    assert set(ctx.canary_via) == {"LAB-IDOR-001", "LAB-SQL-001"}


async def test_modules_disproven_when_patched(lab_factory):
    for mid in ["LAB-INFO-001", "LAB-IDOR-001", "LAB-SQL-001", "LAB-MISCONFIG-001"]:
        tool, _ = lab_factory(patches={mid})
        ctx = AttackContext(canary_token="DRACARYS_CANARY{v4ult-r3c0v3ry-7Q2X-9F1B}")
        target_out = None
        for m in modules_in_order():
            out = await m.run(tool, ctx)
            ctx.merge(out.extracted)
            if m.id == mid:
                target_out = out
                break
        assert target_out is not None
        assert target_out.outcome == TestOutcome.DISPROVEN, f"{mid} should be fixed"


async def test_auth_inconclusive_without_leaked_creds(lab_factory):
    # Running the auth module with an empty context (no INFO step) is inconclusive.
    from dracarys.agents.attacks import ATTACK_MODULES
    tool, _ = lab_factory()
    ctx = AttackContext(canary_token="x")
    out = await ATTACK_MODULES["LAB-AUTH-001"].run(tool, ctx)
    assert out.outcome == TestOutcome.INCONCLUSIVE


def _finding(gt, cat, sev, title, asset):
    f = Finding(campaign_id="c", ground_truth_id=gt, category=cat, title=title,
                severity=sev, affected_asset=asset)
    f.id = "fnd_" + gt
    return f


def _sample_findings():
    return [
        _finding("LAB-INFO-001", VulnCategory.INFO_DISCLOSURE, Severity.HIGH, "info", "GET /api/system/status"),
        _finding("LAB-AUTH-001", VulnCategory.BROKEN_AUTH, Severity.HIGH, "auth", "POST /api/login"),
        _finding("LAB-IDOR-001", VulnCategory.IDOR, Severity.CRITICAL, "idor", "GET /api/accounts/9001"),
        _finding("LAB-SQL-001", VulnCategory.SQL_INJECTION, Severity.CRITICAL, "sqli", "GET /api/accounts/search"),
    ]


def test_graph_builds_chain_to_canary():
    findings = _sample_findings()
    g = build_graph(target_host="127.0.0.1", findings=findings,
                    leaked_identity="qa_bot", canary_finding_ids={"LAB-IDOR-001", "LAB-SQL-001"})
    edge_types = {e["type"] for e in g.edges}
    assert {"enables", "reaches", "authenticates_as", "exposes", "discovers"} <= edge_types
    # The REACHES edges must originate from the vulns that actually reached the
    # canary (IDOR and SQLi) — not any other node.
    reaches_sources = {e["source"] for e in g.edges if e["type"] == "reaches"}
    assert reaches_sources == {"vuln:LAB-IDOR-001", "vuln:LAB-SQL-001"}

    paths = discover_attack_paths(graph=g, findings=findings)
    assert len(paths) == 2
    assert all(p.reaches_canary for p in paths)
    assert all(p.severity == Severity.CRITICAL for p in paths)
    # The two chains end in the two distinct canary-reaching vulns.
    penultimate = {p.nodes[-2]["ref"] for p in paths}
    assert penultimate == {"vuln:LAB-IDOR-001", "vuln:LAB-SQL-001"}


def test_no_canary_paths_when_chain_incomplete():
    # Only info + auth confirmed: no path can reach the canary.
    findings = _sample_findings()[:2]
    g = build_graph(target_host="127.0.0.1", findings=findings,
                    leaked_identity="qa_bot", canary_finding_ids=set())
    paths = discover_attack_paths(graph=g, findings=findings)
    assert all(not p.reaches_canary for p in paths)
