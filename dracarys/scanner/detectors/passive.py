"""Passive detectors — run over already-captured responses (no mutation)."""
from __future__ import annotations

from urllib.parse import urlparse

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, Severity, VulnCategory
from dracarys.scanner.detectors.base import ResponseDetector, make_finding
from dracarys.scanner.models import ScanFinding
from dracarys.scanner.oracles import (
    MISSING_HEADER_CHECKS,
    find_secrets,
    sql_error_signature,
    stack_trace_signature,
)

_SEV = {"medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}


class SecurityHeadersDetector:
    id = "security-headers"

    def inspect(self, url, exchange, ctx):
        headers = {k.lower(): v for k, v in (exchange.response.get("headers", {}) or {}).items()}
        if not headers:
            return []
        findings: list[ScanFinding] = []
        is_https = ctx.base_url.startswith("https")
        for key, name, sev in MISSING_HEADER_CHECKS:
            if key == "strict-transport-security" and not is_https:
                continue
            if key not in headers:
                findings.append(make_finding(
                    detector=self.id, category=VulnCategory.SECURITY_MISCONFIG,
                    title=f"Missing security header: {name}", url=ctx.base_url, method="GET",
                    detail=f"The response does not set the {name} header.",
                    evidence=[LabeledExchange(f"response missing {name}", exchange)],
                    severity=_SEV[sev], confidence=Confidence.CONFIRMED,
                    dedup_key=f"missing-header:{key}",
                ))
        for disclosure in ("server", "x-powered-by"):
            val = headers.get(disclosure)
            if val and any(c.isdigit() for c in val):
                findings.append(make_finding(
                    detector=self.id, category=VulnCategory.INFO_DISCLOSURE,
                    title=f"Technology/version disclosure via {disclosure}",
                    url=ctx.base_url, method="GET",
                    detail=f"The {disclosure} header reveals '{val}'.",
                    evidence=[LabeledExchange(f"{disclosure}: {val}", exchange)],
                    severity=Severity.INFO, dedup_key=f"version-disclosure:{disclosure}",
                ))
        return findings


class SecretsDetector:
    id = "sensitive-data"

    def inspect(self, url, exchange, ctx):
        findings = []
        for label, snippet in find_secrets(exchange.body_text):
            findings.append(make_finding(
                detector=self.id, category=VulnCategory.SENSITIVE_DATA,
                title=f"Sensitive data exposed: {label}", url=url, method="GET",
                detail=f"A response body contained what looks like a {label} ({snippet}).",
                evidence=[LabeledExchange(f"{label} in response", exchange)],
                severity=Severity.HIGH, dedup_key=f"secret:{label}:{urlparse(url).path}",
            ))
        return findings


class VerboseErrorDetector:
    id = "verbose-errors"

    def inspect(self, url, exchange, ctx):
        findings = []
        stack = stack_trace_signature(exchange.body_text)
        if stack:
            findings.append(make_finding(
                detector=self.id, category=VulnCategory.VERBOSE_ERROR,
                title="Verbose error / stack trace disclosed", url=url, method="GET",
                detail=f"The response leaked internal error detail ('{stack[:60]}').",
                evidence=[LabeledExchange("stack trace in response", exchange)],
                dedup_key=f"verbose-error:{urlparse(url).path}",
            ))
        sqlerr = sql_error_signature(exchange.body_text)
        if sqlerr:
            findings.append(make_finding(
                detector=self.id, category=VulnCategory.INFO_DISCLOSURE,
                title="Database error message disclosed", url=url, method="GET",
                detail=f"The response leaked a database error ('{sqlerr[:60]}').",
                evidence=[LabeledExchange("db error in response", exchange)],
                severity=Severity.LOW, dedup_key=f"db-error:{urlparse(url).path}",
            ))
        return findings


PASSIVE_DETECTORS: list[ResponseDetector] = [
    SecurityHeadersDetector(), SecretsDetector(), VerboseErrorDetector(),
]
