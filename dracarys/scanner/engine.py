"""Scan engine — crawl, run detectors, dedupe, and rank findings."""
from __future__ import annotations

import time

from dracarys.logging import get_logger
from dracarys.scanner.crawler import Crawler
from dracarys.scanner.detectors import (
    ALL_SITE_DETECTORS,
    PARAM_DETECTORS,
    PASSIVE_DETECTORS,
)
from dracarys.scanner.detectors.base import send_template
from dracarys.scanner.models import ScanConfig, ScanContext, ScanFinding, ScanResult
from dracarys.tools import HttpTool

log = get_logger("scanner")


class Scanner:
    def __init__(self, tool: HttpTool, base_url: str, config: ScanConfig | None = None) -> None:
        self.ctx = ScanContext(tool=tool, base_url=base_url.rstrip("/"), config=config or ScanConfig())

    def _budget_left(self) -> bool:
        p = self.ctx.tool.policy
        return not p.killed and p.requests_made < p.max_requests

    async def scan(self) -> ScanResult:
        started = time.perf_counter()
        ctx = self.ctx
        result = ScanResult(base_url=ctx.base_url)
        log.info("scan_start", target=ctx.base_url, active=ctx.config.active)

        templates, baselines = await Crawler(ctx).crawl()
        result.pages_crawled = len(baselines)
        result.templates = len(templates)

        findings: list[ScanFinding] = []
        # Passive detectors over every captured response.
        for url, ex in baselines:
            for pdet in PASSIVE_DETECTORS:
                findings.extend(pdet.inspect(url, ex, ctx))

        # Active param detectors over each injection point.
        if ctx.config.active:
            for t in templates:
                if not self._budget_left():
                    log.warning("budget_exhausted", made=ctx.tool.policy.requests_made)
                    break
                baseline = await send_template(ctx, t, note="active baseline")
                for pdet in PASSIVE_DETECTORS:  # also scan API endpoints not reached by crawl
                    findings.extend(pdet.inspect(t.url, baseline, ctx))
                for point in t.injection_points:
                    if not self._budget_left():
                        break
                    for adet in PARAM_DETECTORS:
                        try:
                            findings.extend(await adet.probe(t, point, baseline, ctx))
                        except Exception as exc:  # noqa: BLE001
                            log.warning("detector_error", detector=adet.id, error=str(exc))

        # Site-level detectors (exposed files, API schema, IDOR).
        for sdet in ALL_SITE_DETECTORS:
            if not self._budget_left():
                break
            try:
                findings.extend(await sdet.run(ctx))
            except Exception as exc:  # noqa: BLE001
                log.warning("detector_error", detector=sdet.id, error=str(exc))

        # Dedupe + rank.
        deduped: dict[str, ScanFinding] = {}
        for f in findings:
            deduped.setdefault(f.dedup_key, f)
        result.findings = sorted(
            deduped.values(),
            key=lambda f: (f.severity.rank, f.confidence.value), reverse=True,
        )
        result.requests_made = ctx.tool.policy.requests_made
        result.duration_ms = int((time.perf_counter() - started) * 1000)
        log.info("scan_done", findings=len(result.findings), requests=result.requests_made)
        return result
