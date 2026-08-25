"""Report generation for scan results: JSON, SARIF 2.1.0, Markdown, and HTML.

SARIF makes findings first-class in GitHub code scanning (the Security tab), which
is the primary integration path for the marketplace GitHub Action.
"""
from __future__ import annotations

import html
import json
from datetime import UTC, datetime

from dracarys.domain.enums import Severity
from dracarys.scanner.models import ScanFinding, ScanResult

try:  # keep the reported version in step with the installed package
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("dracarys-dast")
except Exception:  # pragma: no cover - source checkout without install metadata
    __version__ = "0.0.0+dev"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SEV_COLOR = {
    "critical": "#ff3b30", "high": "#ff6b2b", "medium": "#ffd166",
    "low": "#4aa8ff", "info": "#8a90a2",
}


def _finding_dict(f: ScanFinding) -> dict:
    return {
        "detector": f.detector, "category": f.category.value, "severity": f.severity.value,
        "confidence": f.confidence.value, "title": f.title, "url": f.url,
        "method": f.method, "param": f.param, "cwe": f.cwe, "detail": f.detail,
        "remediation": f.remediation, "dedup_key": f.dedup_key,
        "evidence": [
            {
                "label": e.label,
                "request": {k: e.exchange.request.get(k) for k in ("method", "url")},
                "status": e.exchange.status_code,
                "sha256": e.exchange.sha256,
            }
            for e in f.evidence
        ],
    }


def to_json(result: ScanResult) -> str:
    return json.dumps({
        "tool": "dracarys", "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "target": result.base_url,
        "stats": {
            "pages_crawled": result.pages_crawled, "templates": result.templates,
            "requests_made": result.requests_made, "duration_ms": result.duration_ms,
        },
        "severity_breakdown": result.by_severity(),
        "findings": [_finding_dict(f) for f in result.findings],
    }, indent=2)


def to_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rule_id = f.category.value
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.category.value.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f.title},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[-1]}.html",
                "properties": {"cwe": f.cwe, "tags": ["security", f.cwe]},
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {f.detail}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
            "properties": {
                "security-severity": _security_severity(f.severity),
                "cwe": f.cwe, "confidence": f.confidence.value, "param": f.param,
                "detector": f.detector,
            },
        })
    return json.dumps({
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "DRACARYS", "informationUri": "https://github.com/Aman-Thaper/dracarys",
                "version": __version__, "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }, indent=2)


def _security_severity(sev: Severity) -> str:
    return {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}[sev.value]


def to_markdown(result: ScanResult) -> str:
    b = result.by_severity()
    lines = [
        f"# DRACARYS scan report — `{result.base_url}`", "",
        f"- **Findings:** {len(result.findings)}  "
        f"(critical {b['critical']} · high {b['high']} · medium {b['medium']} · low {b['low']} · info {b['info']})",
        f"- **Crawled:** {result.pages_crawled} pages, {result.templates} request templates",
        f"- **Requests:** {result.requests_made}  ·  **Duration:** {result.duration_ms} ms", "",
        "| Severity | Category | CWE | Location | Param | Confidence |",
        "|---|---|---|---|---|---|",
    ]
    for f in result.findings:
        lines.append(
            f"| {f.severity.value} | {f.category.value} | {f.cwe} | "
            f"`{f.method} {f.url}` | {f.param or '—'} | {f.confidence.value} |"
        )
    lines += ["", "## Details", ""]
    for f in result.findings:
        lines += [
            f"### {f.title}  ({f.severity.value.upper()}, {f.cwe})",
            f"- **Location:** `{f.method} {f.url}`" + (f"  param `{f.param}`" if f.param else ""),
            "- **Evidence:** " + "; ".join(
                f"{e.label} → HTTP {e.exchange.status_code} (sha256 {e.exchange.sha256[:10]})"
                for e in f.evidence
            ),
            f"- **Why:** {f.detail}",
            f"- **Fix:** {f.remediation}", "",
        ]
    return "\n".join(lines)


def to_html(result: ScanResult) -> str:
    b = result.by_severity()
    rows = []
    for f in result.findings:
        color = _SEV_COLOR[f.severity.value]
        ev = "".join(
            f"<div class='ev'><span>{html.escape(e.label)}</span>"
            f"<code>{html.escape(str(e.exchange.request.get('method','')))} "
            f"{html.escape(str(e.exchange.request.get('url','')))} → {e.exchange.status_code}</code></div>"
            for e in f.evidence
        )
        rows.append(f"""
        <details class="finding">
          <summary><span class="sev" style="background:{color}22;color:{color};border-color:{color}66">
            {f.severity.value}</span> <b>{html.escape(f.title)}</b>
            <span class="cwe">{f.cwe}</span></summary>
          <div class="body">
            <div class="loc"><code>{html.escape(f.method)} {html.escape(f.url)}</code>
              {f'<span class="param">param: {html.escape(f.param)}</span>' if f.param else ''}</div>
            <p>{html.escape(f.detail)}</p>
            <div class="evs">{ev}</div>
            <div class="fix"><b>Fix:</b> {html.escape(f.remediation)}</div>
          </div>
        </details>""")
    counts = " · ".join(
        f"<span style='color:{_SEV_COLOR[k]}'>{k} {v}</span>" for k, v in b.items() if v
    ) or "no findings"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>DRACARYS scan — {html.escape(result.base_url)}</title>
<style>
 body{{background:#07080c;color:#d7dbe4;font-family:ui-monospace,Menlo,monospace;margin:0;padding:28px;}}
 h1{{color:#ff6b2b;}} .meta{{color:#8a90a2;font-size:13px;margin-bottom:18px;}}
 .finding{{border:1px solid #212636;border-radius:8px;margin:8px 0;background:#0d0f16;}}
 summary{{cursor:pointer;padding:12px 14px;list-style:none;}}
 .sev{{border:1px solid;border-radius:4px;padding:1px 8px;font-size:11px;text-transform:uppercase;}}
 .cwe{{color:#8a90a2;font-size:12px;float:right;}}
 .body{{padding:0 14px 14px;border-top:1px solid #212636;}}
 .loc code{{color:#4aa8ff;}} .param{{color:#ffd166;margin-left:10px;font-size:12px;}}
 .ev{{background:#07080c;border:1px solid #212636;border-radius:6px;padding:6px 8px;margin:4px 0;font-size:12px;}}
 .ev span{{color:#8a90a2;margin-right:8px;}} .ev code{{color:#39d98a;}}
 .fix{{margin-top:8px;color:#9ecbff;font-size:13px;}}
</style></head><body>
 <h1>🐉 DRACARYS scan report</h1>
 <div class="meta">target <b>{html.escape(result.base_url)}</b> · {counts} ·
   {result.pages_crawled} pages · {result.requests_made} requests · {result.duration_ms} ms</div>
 {''.join(rows) or '<p>No findings.</p>'}
</body></html>"""
