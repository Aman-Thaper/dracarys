"""Detector base types and request helpers."""
from __future__ import annotations

from typing import Protocol

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, Severity, VulnCategory
from dracarys.scanner.cwe import DEFAULT_SEVERITY, cwe_for, remediation_for
from dracarys.scanner.models import (
    InjectionPoint,
    RequestTemplate,
    ScanContext,
    ScanFinding,
)
from dracarys.tools.base import HttpExchange


def make_finding(
    *, detector: str, category: VulnCategory, title: str, url: str, method: str,
    detail: str, evidence: list[LabeledExchange], param: str | None = None,
    severity: Severity | None = None, confidence: Confidence = Confidence.CONFIRMED,
    dedup_key: str = "",
) -> ScanFinding:
    return ScanFinding(
        detector=detector, category=category,
        severity=severity or DEFAULT_SEVERITY.get(category, Severity.MEDIUM),
        confidence=confidence, title=title, url=url, method=method, detail=detail,
        cwe=cwe_for(category), remediation=remediation_for(category),
        param=param, evidence=evidence, dedup_key=dedup_key,
    ).finalize()


async def send_template(
    ctx: ScanContext, template: RequestTemplate,
    *, params: dict | None = None, url: str | None = None, note: str = "",
) -> HttpExchange:
    p = template.params if params is None else params
    target = url or template.url
    headers = {**ctx.config.auth_headers, **template.headers}
    if template.body_kind == "form" and template.method != "GET":
        return await ctx.tool.send(template.method, target, data=p, headers=headers, note=note)
    if template.body_kind == "json" and template.method != "GET":
        return await ctx.tool.send(template.method, target, json=p, headers=headers, note=note)
    return await ctx.tool.send(template.method, target, params=p or None, headers=headers, note=note)


async def mutate(
    ctx: ScanContext, template: RequestTemplate, point: InjectionPoint, value: str,
    *, note: str = "",
) -> HttpExchange:
    """Send the template with a single injection point replaced by ``value``."""
    if point.where == "path":
        base_val = template.params.get(point.name, "")
        url = template.url.replace(f"{{{point.name}}}", value)
        if base_val and base_val in template.url:
            url = template.url.replace(base_val, value)
        return await send_template(ctx, template, url=url, note=note)
    params = dict(template.params)
    params[point.name] = value
    return await send_template(ctx, template, params=params, note=note)


class ResponseDetector(Protocol):
    id: str
    def inspect(self, url: str, exchange: HttpExchange, ctx: ScanContext) -> list[ScanFinding]: ...


class ParamDetector(Protocol):
    id: str
    async def probe(self, template: RequestTemplate, point: InjectionPoint,
                    baseline: HttpExchange, ctx: ScanContext) -> list[ScanFinding]: ...


class SiteDetector(Protocol):
    id: str
    async def run(self, ctx: ScanContext) -> list[ScanFinding]: ...
