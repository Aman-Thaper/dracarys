"""DRACARYS command-line interface.

    dracarys serve            # run the control-plane API
    dracarys lab [--port]     # run the vulnerable lab as a standalone service
    dracarys demo             # run a full headless campaign and print a report
    dracarys eval             # run a campaign and score it against ground truth
"""
from __future__ import annotations

import argparse
import asyncio
import json

from dracarys.config import get_settings
from dracarys.logging import configure_logging, get_logger

log = get_logger("cli")


async def _run_campaign_headless(settings):
    from dracarys.db.base import Database
    from dracarys.db.models import Campaign, Target
    from dracarys.engine.orchestrator.lab_controller import InProcessLabController
    from dracarys.engine.orchestrator.orchestrator import Orchestrator
    from lab.ground_truth import CANARY_TOKEN

    db = Database(settings)
    await db.create_all()
    async with db.session_factory() as s:
        target = Target(
            name="DRACARYS BANK (lab)", base_url=settings.lab_base_url,
            allowed_hosts=[settings.lab_host, "127.0.0.1", "localhost"],
            allowed_ports=[settings.lab_port, settings.lab_patched_port], is_lab=True,
        )
        s.add(target)
        await s.flush()
        campaign = Campaign(
            target_id=target.id, name="CLI demo",
            objective="Discover and prove an attack chain, then verify fixes.",
            policy={"canary_token": CANARY_TOKEN},
        )
        s.add(campaign)
        await s.flush()
        cid = campaign.id
        await s.commit()

    orch = Orchestrator(db, InProcessLabController(settings), settings=settings)
    await orch.run_campaign(cid)
    return db, cid


def _print_report(campaign, findings, paths, retests):
    print("\n" + "=" * 68)
    print(f"  DRACARYS CAMPAIGN {campaign.id}")
    print("=" * 68)
    print(f"  State: {campaign.state.value}   Security score: {campaign.security_score}/100"
          f"   Requests: {campaign.requests_made}")
    print(f"  Target compromised: {campaign.progress.get('target_compromised')}")
    print("\n  FINDINGS")
    for f in sorted(findings, key=lambda x: x.ground_truth_id or ""):
        print(f"    [{f.severity.value:8s}] {f.ground_truth_id:18s} {f.status.value:14s} {f.title}")
    print("\n  ATTACK PATHS")
    for p in paths:
        flag = "  *** REACHES CANARY ***" if p.reaches_canary else ""
        print(f"    {p.title}{flag}")
    print("\n  RETEST")
    verified = sum(1 for r in retests if r.result.value == "fix_verified")
    print(f"    FIX VERIFIED: {verified}/{len(retests)}")
    print("=" * 68 + "\n")


def cmd_demo(args) -> int:
    settings = get_settings()

    async def run():
        from sqlalchemy import select

        from dracarys.db.models import AttackPath, Campaign, Finding, Retest
        db, cid = await _run_campaign_headless(settings)
        async with db.session_factory() as s:
            c = await s.get(Campaign, cid)
            finds = (await s.execute(select(Finding).where(Finding.campaign_id == cid))).scalars().all()
            paths = (await s.execute(select(AttackPath).where(AttackPath.campaign_id == cid))).scalars().all()
            rts = (await s.execute(select(Retest).where(Retest.campaign_id == cid))).scalars().all()
            _print_report(c, list(finds), list(paths), list(rts))
        await db.dispose()

    asyncio.run(run())
    return 0


def cmd_eval(args) -> int:
    settings = get_settings()

    async def run():
        from dracarys.evaluation import evaluate_campaign
        db, cid = await _run_campaign_headless(settings)
        metrics = await evaluate_campaign(db, cid)
        print(json.dumps(metrics.to_dict(), indent=2))
        await db.dispose()
        ok = metrics.recall == 1.0 and metrics.precision == 1.0 and metrics.retest_success == 1.0
        print("\nRESULT:", "PASS ✓" if ok else "FAIL ✗")
        return 0 if ok else 1

    return asyncio.run(run())


def _parse_headers(pairs) -> dict:
    out = {}
    for item in pairs or []:
        if ":" in item:
            k, v = item.split(":", 1)
            out[k.strip()] = v.strip()
    return out


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _print_scan_table(result) -> None:
    b = result.by_severity()
    print("\n" + "=" * 74)
    print(f"  DRACARYS SCAN  {result.base_url}")
    print("=" * 74)
    print(f"  {len(result.findings)} findings  |  "
          f"critical {b['critical']} · high {b['high']} · medium {b['medium']} · "
          f"low {b['low']} · info {b['info']}")
    print(f"  {result.pages_crawled} pages · {result.templates} templates · "
          f"{result.requests_made} requests · {result.duration_ms} ms\n")
    for f in result.findings:
        loc = f.param and f"{f.url} [{f.param}]" or f.url
        print(f"  [{f.severity.value:8s}] {f.cwe:8s} {f.category.value:16s} {loc}")
    print("=" * 74)


def cmd_scan(args) -> int:
    from dracarys.scanner import ScanConfig
    from dracarys.scanner import report as _report
    from dracarys.scanner.runner import authorize, run_scan

    auth = authorize(args.url, args.yes_i_am_authorized)
    if not auth.ok:
        print(f"error: {auth.reason}")
        return 2

    config = ScanConfig(
        active=not args.passive,
        include_time_based=not args.no_time,
        max_pages=args.max_pages,
        auth_headers=_parse_headers(args.auth),
        second_identity_headers=_parse_headers(args.second_auth) or None,
        protected_urls=list(args.protected_url or []),
    )

    async def run():
        return await run_scan(args.url, config, extra_hosts=list(args.scope or []),
                              max_requests=args.max_requests)

    result = asyncio.run(run())

    renderers = {
        "json": _report.to_json, "sarif": _report.to_sarif,
        "md": _report.to_markdown, "html": _report.to_html,
    }
    # Additional report files from the single scan (used by CI / the Action).
    for fmt, path in (("sarif", args.sarif), ("md", args.md),
                      ("html", args.html), ("json", args.json)):
        if path:
            with open(path, "w") as fh:
                fh.write(renderers[fmt](result))
            print(f"wrote {fmt} report to {path}")
    # Primary output to stdout / --out.
    if args.format in renderers:
        text = renderers[args.format](result)
        if args.out:
            with open(args.out, "w") as fh:
                fh.write(text)
            print(f"wrote {args.format} report to {args.out}")
        else:
            print(text)
    else:
        _print_scan_table(result)

    if args.fail_on != "none":
        threshold = _SEV_RANK[args.fail_on]
        worst = max((_SEV_RANK[f.severity.value] for f in result.findings), default=-1)
        if worst >= threshold:
            return 1
    return 0


def cmd_scan_selftest(args) -> int:
    import json as _json

    from dracarys.evaluation.scanner_eval import evaluate_fixtures
    metrics = asyncio.run(evaluate_fixtures())
    print(_json.dumps(metrics.to_dict(), indent=2))
    ok = metrics.recall >= 0.95 and metrics.false_positives_safe == 0
    print("\nRESULT:", "PASS ✓" if ok else "FAIL ✗")
    return 0 if ok else 1


def cmd_serve(args) -> int:
    import uvicorn
    settings = get_settings()
    uvicorn.run("dracarys.api.app:app", host=settings.api_host, port=settings.api_port,
                reload=args.reload)
    return 0


def cmd_lab(args) -> int:
    import uvicorn

    from lab.app import create_lab_app
    patches = {p.strip() for p in (args.patches or "").split(",") if p.strip()}
    app = create_lab_app(patches)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


def main() -> None:
    configure_logging()
    parser = argparse.ArgumentParser(prog="dracarys", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_serve = sub.add_parser("serve", help="run the control-plane API")
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    p_lab = sub.add_parser("lab", help="run the vulnerable lab")
    p_lab.add_argument("--host", default=get_settings().lab_host)
    p_lab.add_argument("--port", type=int, default=get_settings().lab_port)
    p_lab.add_argument("--patches", default="")
    p_lab.set_defaults(func=cmd_lab)

    p_demo = sub.add_parser("demo", help="run a full headless campaign")
    p_demo.set_defaults(func=cmd_demo)

    p_eval = sub.add_parser("eval", help="run a campaign and score it")
    p_eval.set_defaults(func=cmd_eval)

    p_scan = sub.add_parser("scan", help="scan an authorized HTTP target for vulnerabilities")
    p_scan.add_argument("url", help="target base URL, e.g. http://127.0.0.1:8888")
    p_scan.add_argument("--passive", action="store_true", help="passive checks only (no injection)")
    p_scan.add_argument("--no-time", action="store_true", help="disable time-based SQLi probes")
    p_scan.add_argument("--auth", action="append", metavar="'Header: value'",
                        help="auth header for the scanner (repeatable)")
    p_scan.add_argument("--second-auth", action="append", metavar="'Header: value'",
                        help="second identity header for IDOR testing (repeatable)")
    p_scan.add_argument("--protected-url", action="append", metavar="URL",
                        help="URL owned by the second identity (repeatable, for IDOR)")
    p_scan.add_argument("--scope", action="append", metavar="HOST",
                        help="additional in-scope host (repeatable)")
    p_scan.add_argument("--max-pages", type=int, default=60)
    p_scan.add_argument("--max-requests", type=int, default=3000)
    p_scan.add_argument("--format", choices=["table", "json", "sarif", "md", "html"], default="table")
    p_scan.add_argument("--out", metavar="FILE", help="write the primary --format report to a file")
    p_scan.add_argument("--sarif", metavar="FILE", help="also write a SARIF report")
    p_scan.add_argument("--md", metavar="FILE", help="also write a Markdown report")
    p_scan.add_argument("--html", metavar="FILE", help="also write an HTML report")
    p_scan.add_argument("--json", metavar="FILE", help="also write a JSON report")
    p_scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"],
                        default="high", help="exit non-zero if a finding at/above this severity is found")
    p_scan.add_argument("--yes-i-am-authorized", action="store_true",
                        help="confirm you are authorized to scan a non-loopback target")
    p_scan.set_defaults(func=cmd_scan)

    p_selftest = sub.add_parser("scan-selftest",
        help="score the generic detectors against independent fixture apps")
    p_selftest.set_defaults(func=cmd_scan_selftest)

    args = parser.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
