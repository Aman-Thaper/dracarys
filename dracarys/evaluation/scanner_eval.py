"""Generalization scorecard for the generic scanner.

Scans independent fixture apps (unlike the DRACARYS lab) and scores how many of
their known vulnerability classes are detected, plus false positives on a hardened
control app. This is the honest measure that detection generalizes.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

import httpx

from dracarys.engine.policy import PolicyEngine, Scope
from dracarys.scanner import ScanConfig, Scanner
from dracarys.tools import HttpTool

SERIOUS = {"sql_injection", "xss", "open_redirect", "idor", "exposed_resource"}


@dataclass
class ScannerEval:
    expected: int
    detected: int
    recall: float
    per_app: dict = field(default_factory=dict)
    false_positives_safe: int = 0
    false_positive_categories: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _tool(app, base, port):
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)
    policy = PolicyEngine(Scope.create(["127.0.0.1"], [port]),
                          max_requests=4000, max_concurrency=4, timeout_seconds=8)
    return HttpTool(base, policy, client), client


async def evaluate_fixtures() -> ScannerEval:
    from dracarys.scanner.testbed import (
        FIXTURE_GROUND_TRUTH,
        build_api_app,
        build_blog_app,
        build_safe_app,
    )

    apps = {
        "blog": (build_blog_app(), 8888, ScanConfig(active=True, include_time_based=False)),
        "api": (build_api_app(), 8889, ScanConfig(
            active=True, include_time_based=False,
            auth_headers={"Authorization": "Bearer tok-user1"},
            second_identity_headers={"Authorization": "Bearer tok-user2"},
            protected_urls=["http://127.0.0.1:8889/api/v2/notes/1001"])),
    }
    per_app, total_expected, total_detected = {}, 0, 0
    for name, (app, port, cfg) in apps.items():
        base = f"http://127.0.0.1:{port}"
        tool, client = _tool(app, base, port)
        try:
            res = await Scanner(tool, base, cfg).scan()
        finally:
            await client.aclose()
        found = {f.category.value for f in res.findings}
        expected = {cat for cat, _ in FIXTURE_GROUND_TRUTH[name]}
        hit = expected & found
        per_app[name] = {
            "expected": sorted(expected), "found": sorted(found),
            "missed": sorted(expected - found), "recall": round(len(hit) / len(expected), 3),
        }
        total_expected += len(expected)
        total_detected += len(hit)

    # False positives on a hardened control app.
    base = "http://127.0.0.1:8888"
    tool, client = _tool(build_safe_app(), base, 8888)
    try:
        safe = await Scanner(tool, base, ScanConfig(active=True, include_time_based=False)).scan()
    finally:
        await client.aclose()
    fp = sorted({f.category.value for f in safe.findings} & SERIOUS)

    return ScannerEval(
        expected=total_expected, detected=total_detected,
        recall=round(total_detected / total_expected, 3) if total_expected else 0.0,
        per_app=per_app, false_positives_safe=len(fp), false_positive_categories=fp,
    )
