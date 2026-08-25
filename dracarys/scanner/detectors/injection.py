"""Active injection detectors: SQLi, reflected XSS, open redirect.

All payloads are read-only and non-destructive (no DROP/DELETE/UPDATE, only short
sleeps, benign markers). Each detector confirms via a deterministic oracle and
captures the paired baseline/attack exchanges as evidence.
"""
from __future__ import annotations

from urllib.parse import urlparse

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, VulnCategory
from dracarys.scanner.detectors.base import ParamDetector, make_finding, mutate
from dracarys.scanner.oracles import (
    boolean_divergence,
    reflects_unencoded,
    sql_error_signature,
    time_delayed,
)

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),            # string context
    ("%' AND '1'='1'-- -", "%' AND '1'='2'-- -"),  # LIKE '%..%' context
    ("' AND '1'='1'-- -", "' AND '1'='2'-- -"),    # string + comment
    (" AND 1=1", " AND 1=2"),                      # numeric context
    (" AND 1=1-- -", " AND 1=2-- -"),              # numeric + comment
]

REDIRECT_PARAM_HINTS = {
    "url", "next", "redirect", "redirect_uri", "redirecturl", "return", "returnurl",
    "returnto", "dest", "destination", "continue", "goto", "target", "u", "r", "link", "out",
}


class SqlInjectionDetector:
    id = "sqli"
    category = VulnCategory.SQL_INJECTION

    async def probe(self, template, point, baseline, ctx):
        base_val = template.params.get(point.name, "1")
        # 1) Error-based
        for suffix in ("'", '"', "')", "';"):
            ex = await mutate(ctx, template, point, base_val + suffix,
                              note=f"sqli error probe on {point.name}")
            sig = sql_error_signature(ex.body_text)
            if sig and not sql_error_signature(baseline.body_text):
                return [self._finding(template, point, "error-based",
                        f"Injecting `{suffix}` produced a database error ('{sig[:50]}').",
                        [("baseline", baseline), ("error-based injection", ex)],
                        Confidence.CONFIRMED)]
        # 2) Boolean-based — try common injection contexts (string, LIKE, numeric).
        for t_suffix, f_suffix in BOOLEAN_PAIRS:
            truthy = await mutate(ctx, template, point, base_val + t_suffix,
                                  note=f"sqli boolean TRUE on {point.name}")
            falsy = await mutate(ctx, template, point, base_val + f_suffix,
                                 note=f"sqli boolean FALSE on {point.name}")
            if boolean_divergence(baseline, truthy, falsy):
                return [self._finding(template, point, "boolean-based",
                        "A TRUE condition matched the baseline while a FALSE condition "
                        "diverged, proving the parameter alters query logic.",
                        [("baseline", baseline), ("TRUE condition", truthy),
                         ("FALSE condition", falsy)],
                        Confidence.FIRM)]
        # 3) Time-based (only if enabled; harmless short sleeps)
        if ctx.config.include_time_based:
            control = await mutate(ctx, template, point, base_val,
                                   note=f"sqli time control on {point.name}")
            for payload in (
                f"{base_val}' AND (SELECT 1 FROM (SELECT SLEEP(3))x)-- -",
                f"{base_val}';SELECT pg_sleep(3)-- -",
            ):
                ex = await mutate(ctx, template, point, payload,
                                  note=f"sqli time probe on {point.name}")
                if time_delayed(control.elapsed_ms, ex.elapsed_ms, 3):
                    return [self._finding(template, point, "time-based",
                            f"A time-delay payload made the response take "
                            f"{ex.elapsed_ms}ms vs {control.elapsed_ms}ms control.",
                            [("no-delay control", control), ("time-delay injection", ex)],
                            Confidence.CONFIRMED)]
        return []

    def _finding(self, template, point, kind, detail, exchanges, conf):
        return make_finding(
            detector=self.id, category=self.category,
            title=f"SQL injection ({kind}) in '{point.name}'",
            url=template.url, method=template.method, param=point.name,
            detail=detail, confidence=conf,
            evidence=[LabeledExchange(lbl, ex) for lbl, ex in exchanges],
        )


class XssDetector:
    id = "xss"
    category = VulnCategory.XSS

    async def probe(self, template, point, baseline, ctx):
        marker = ctx.marker("x")
        payload = f"{marker}<svg/onload=1>"
        ex = await mutate(ctx, template, point, payload,
                          note=f"reflected xss probe on {point.name}")
        if reflects_unencoded(payload, ex):
            return [make_finding(
                detector=self.id, category=self.category,
                title=f"Reflected XSS in '{point.name}'",
                url=template.url, method=template.method, param=point.name,
                detail="A unique HTML payload was reflected unencoded into an HTML "
                       "response, allowing script injection.",
                evidence=[LabeledExchange("baseline", baseline),
                          LabeledExchange("reflected payload", ex)],
                confidence=Confidence.CONFIRMED,
            )]
        return []


class OpenRedirectDetector:
    id = "open-redirect"
    category = VulnCategory.OPEN_REDIRECT

    async def probe(self, template, point, baseline, ctx):
        if point.name.lower() not in REDIRECT_PARAM_HINTS:
            return []
        evil = "dcrs-oob.example"
        for payload in (f"https://{evil}/", f"//{evil}/"):
            ex = await mutate(ctx, template, point, payload,
                              note=f"open redirect probe on {point.name}")
            loc = (ex.response.get("headers", {}) or {}).get("location", "")
            if ex.status_code in (301, 302, 303, 307, 308) and evil in urlparse(loc).netloc:
                return [make_finding(
                    detector=self.id, category=self.category,
                    title=f"Open redirect via '{point.name}'",
                    url=template.url, method=template.method, param=point.name,
                    detail=f"Setting {point.name} redirected (Location: {loc}) to an "
                           "attacker-controlled host.",
                    evidence=[LabeledExchange("open redirect", ex)],
                    confidence=Confidence.CONFIRMED,
                )]
        return []


PARAM_DETECTORS: list[ParamDetector] = [
    SqlInjectionDetector(), XssDetector(), OpenRedirectDetector(),
]
