"""MCP server exposing DRACARYS scanning to MCP-capable agents.

Run with `dracarys-mcp` (stdio transport). Install the optional dependency first:

    pip install "dracarys-dast[mcp]"

The same safety boundary as the CLI applies here — `runner.authorize` gates every
scan, so an agent cannot point this at an arbitrary host without the caller
explicitly asserting authorization. Findings are still produced by deterministic
oracles; the model consuming this server never decides whether a bug is real.
"""
from __future__ import annotations

import json
from typing import Any

from dracarys.scanner import ScanConfig
from dracarys.scanner.cwe import CWE, REMEDIATION
from dracarys.scanner.report import to_json, to_markdown
from dracarys.scanner.runner import authorize, run_scan


def _parse_headers(raw: list[str] | None) -> dict[str, str]:
    """Parse 'Name: value' strings into a header mapping."""
    out: dict[str, str] = {}
    for item in raw or []:
        name, _, value = item.partition(":")
        if not _ or not name.strip():
            raise ValueError(f"auth header must be 'Name: value', got {item!r}")
        out[name.strip()] = value.strip()
    return out


async def scan_target(
    target: str,
    authorized: bool = False,
    passive: bool = False,
    max_pages: int = 60,
    include_time_based: bool = True,
    auth_headers: list[str] | None = None,
    output: str = "summary",
) -> str:
    """Run a DAST scan against an authorized target and return the findings.

    Args:
        target: Base URL to scan, e.g. http://127.0.0.1:8000.
        authorized: Must be True for any non-loopback target. Set it only when the
            operator has confirmed they are authorized to test that system.
        passive: Passive checks only — no injection probes are sent.
        max_pages: Crawl budget.
        include_time_based: Allow short time-based SQLi probes.
        auth_headers: Optional headers as 'Name: value' strings.
        output: "summary" (compact), "json" (full findings), or "markdown".
    """
    gate = authorize(target, authorized)
    if not gate.ok:
        return json.dumps({"error": gate.reason, "target": target}, indent=2)

    config = ScanConfig(
        active=not passive,
        include_time_based=include_time_based,
        max_pages=max_pages,
        auth_headers=_parse_headers(auth_headers),
    )
    result = await run_scan(target, config)

    if output == "json":
        return to_json(result)
    if output == "markdown":
        return to_markdown(result)

    return json.dumps(
        {
            "target": result.base_url,
            "severity_breakdown": result.by_severity(),
            "stats": {
                "pages_crawled": result.pages_crawled,
                "templates": result.templates,
                "requests_made": result.requests_made,
                "duration_ms": result.duration_ms,
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "category": f.category.value,
                    "cwe": f.cwe,
                    "method": f.method,
                    "url": f.url,
                    "param": f.param,
                    "detail": f.detail,
                    "evidence_count": len(f.evidence),
                }
                for f in result.findings
            ],
        },
        indent=2,
    )


def list_detectors() -> str:
    """List the vulnerability classes DRACARYS detects, with CWE ids."""
    return json.dumps(
        [
            {
                "category": cat.value,
                "cwe": cwe_id,
                "remediation": REMEDIATION.get(cat, ""),
            }
            for cat, cwe_id in sorted(CWE.items(), key=lambda kv: kv[0].value)
        ],
        indent=2,
    )


def _load_server_class() -> Any:
    """Return the high-level server class across mcp SDK generations.

    The SDK renamed `mcp.server.fastmcp.FastMCP` (1.x) to `mcp.server.MCPServer`
    (2.x); both expose the same `.tool()` decorator and `.run(transport=...)`.
    """
    import importlib

    for module_name, attr in (("mcp.server", "MCPServer"), ("mcp.server.fastmcp", "FastMCP")):
        try:
            return getattr(importlib.import_module(module_name), attr)
        except (ImportError, AttributeError):
            continue
    raise SystemExit(  # pragma: no cover - depends on optional extra
        "The MCP server needs the optional 'mcp' dependency.\n"
        '  pip install "dracarys-dast[mcp]"'
    )


def build_server() -> Any:
    """Construct the MCP server. Imported lazily so `mcp` stays optional."""
    server_cls = _load_server_class()
    server = server_cls(
        "dracarys",
        instructions=(
            "DRACARYS is an evidence-first DAST scanner. Every finding is confirmed "
            "by a deterministic oracle plus captured request/response evidence. Only "
            "scan systems the operator is authorized to test: non-loopback targets "
            "require authorized=true, which you must not set on your own initiative."
        ),
    )
    server.tool()(scan_target)
    server.tool()(list_detectors)
    return server


def main() -> None:
    """Entry point for the `dracarys-mcp` console script (stdio transport)."""
    build_server().run()


if __name__ == "__main__":  # pragma: no cover
    main()
