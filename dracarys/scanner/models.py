"""Data models for the generic scanner."""
from __future__ import annotations

import secrets as _secrets
from dataclasses import dataclass, field

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, Severity, VulnCategory
from dracarys.tools import HttpTool


@dataclass(frozen=True)
class InjectionPoint:
    where: str   # "query" | "form" | "path"
    name: str


@dataclass
class RequestTemplate:
    method: str
    url: str                                  # absolute; query carried in params
    params: dict[str, str] = field(default_factory=dict)
    body_kind: str = "query"                  # "query" | "form" | "json"
    headers: dict = field(default_factory=dict)
    injection_points: list[InjectionPoint] = field(default_factory=list)
    source: str = "crawl"

    def key(self) -> str:
        return f"{self.method} {self.url} [{','.join(sorted(self.params))}]"


@dataclass
class ScanFinding:
    detector: str
    category: VulnCategory
    severity: Severity
    confidence: Confidence
    title: str
    url: str
    method: str
    detail: str
    cwe: str
    remediation: str
    param: str | None = None
    evidence: list[LabeledExchange] = field(default_factory=list)
    dedup_key: str = ""

    def finalize(self) -> ScanFinding:
        if not self.dedup_key:
            self.dedup_key = f"{self.category.value}:{self.method}:{self.url}:{self.param or '-'}"
        return self


@dataclass
class ScanConfig:
    active: bool = True                 # run active injection probes (vs passive only)
    include_time_based: bool = True     # allow (short) time-based SQLi probes
    max_pages: int = 60
    max_depth: int = 3
    auth_headers: dict = field(default_factory=dict)
    # Optional second identity for differential BOLA/IDOR testing.
    second_identity_headers: dict | None = None
    # URLs accessible to the second identity; identity 1 will attempt to reach them.
    protected_urls: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    tool: HttpTool
    base_url: str
    config: ScanConfig
    run_id: str = field(default_factory=lambda: _secrets.token_hex(4))

    def marker(self, tag: str = "") -> str:
        return f"dcrs{self.run_id}{tag}{_secrets.token_hex(3)}"


@dataclass
class ScanResult:
    base_url: str
    findings: list[ScanFinding] = field(default_factory=list)
    pages_crawled: int = 0
    templates: int = 0
    requests_made: int = 0
    duration_ms: int = 0

    def by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out
