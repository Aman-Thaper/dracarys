"""Site-level detectors: sensitive exposed files and endpoints (safe GETs only)."""
from __future__ import annotations

from urllib.parse import urljoin

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, Severity, VulnCategory
from dracarys.scanner.detectors.base import SiteDetector, make_finding
from dracarys.scanner.oracles import find_secrets

# path -> (signature substrings, category, severity, title)
SENSITIVE_PATHS = [
    ("/.env", ("=",), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Environment file (.env) exposed"),
    ("/.git/config", ("[core]", "repositoryformatversion"), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Git config exposed"),
    ("/.git/HEAD", ("ref:",), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Git repository exposed"),
    ("/.aws/credentials", ("aws_access_key_id",), VulnCategory.EXPOSED_RESOURCE, Severity.CRITICAL, "AWS credentials file exposed"),
    ("/backup.sql", ("INSERT INTO", "CREATE TABLE"), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Database backup exposed"),
    ("/dump.sql", ("INSERT INTO", "CREATE TABLE"), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Database dump exposed"),
    ("/actuator/env", ("propertySources", "activeProfiles"), VulnCategory.EXPOSED_RESOURCE, Severity.HIGH, "Spring Actuator env exposed"),
    ("/server-status", ("Apache Server Status",), VulnCategory.EXPOSED_RESOURCE, Severity.MEDIUM, "Apache server-status exposed"),
    ("/phpinfo.php", ("phpinfo()", "PHP Version"), VulnCategory.INFO_DISCLOSURE, Severity.MEDIUM, "phpinfo() exposed"),
    ("/.DS_Store", ("Bud1",), VulnCategory.EXPOSED_RESOURCE, Severity.LOW, "macOS .DS_Store exposed"),
]


class ExposedFilesDetector:
    id = "exposed-files"

    async def run(self, ctx):
        findings = []
        for path, sigs, category, severity, title in SENSITIVE_PATHS:
            url = urljoin(ctx.base_url + "/", path.lstrip("/"))
            ex = await ctx.tool.send("GET", url, headers=ctx.config.auth_headers,
                                     note=f"probe sensitive path {path}")
            if ex.status_code != 200 or not ex.body_text:
                continue
            body = ex.body_text
            secrets = find_secrets(body)
            matched = any(sig in body for sig in sigs) or bool(secrets)
            if matched:
                findings.append(make_finding(
                    detector=self.id, category=category, title=title, url=url, method="GET",
                    detail=f"{path} is reachable and returned recognizable sensitive content.",
                    evidence=[LabeledExchange(f"GET {path}", ex)],
                    severity=severity, confidence=Confidence.CONFIRMED,
                    dedup_key=f"exposed:{path}",
                ))
                for label, snippet in secrets:
                    findings.append(make_finding(
                        detector=self.id, category=VulnCategory.SENSITIVE_DATA,
                        title=f"Sensitive data exposed: {label}", url=url, method="GET",
                        detail=f"{path} contained what looks like a {label} ({snippet}).",
                        evidence=[LabeledExchange(f"{label} in {path}", ex)],
                        severity=Severity.HIGH, confidence=Confidence.CONFIRMED,
                        dedup_key=f"secret:{label}:{path}",
                    ))
        return findings


class ExposedApiSchemaDetector:
    id = "exposed-api-schema"

    async def run(self, ctx):
        findings = []
        for path in ("/openapi.json", "/swagger.json", "/api/openapi.json", "/v2/api-docs"):
            url = urljoin(ctx.base_url + "/", path.lstrip("/"))
            ex = await ctx.tool.send("GET", url, headers=ctx.config.auth_headers,
                                     note=f"probe api schema {path}")
            if ex.status_code == 200 and ('"openapi"' in ex.body_text or '"swagger"' in ex.body_text):
                findings.append(make_finding(
                    detector=self.id, category=VulnCategory.INFO_DISCLOSURE,
                    title="API schema publicly exposed", url=url, method="GET",
                    detail=f"An OpenAPI/Swagger schema is served at {path}, mapping the API surface.",
                    evidence=[LabeledExchange(f"GET {path}", ex)],
                    severity=Severity.INFO, dedup_key=f"api-schema:{path}",
                ))
                break
        return findings


SITE_DETECTORS: list[SiteDetector] = [ExposedFilesDetector(), ExposedApiSchemaDetector()]
