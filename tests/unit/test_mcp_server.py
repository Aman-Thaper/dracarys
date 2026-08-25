"""Unit tests for the MCP server surface.

These cover the parts that must hold without the optional `mcp` dependency
installed: header parsing, the detector catalogue, and — most importantly —
that the authorization gate still refuses non-loopback targets when an agent
calls the tool.
"""
from __future__ import annotations

import json

import pytest

from dracarys.mcp_server import _parse_headers, list_detectors, scan_target


def test_parse_headers_splits_name_and_value():
    assert _parse_headers(["Authorization: Bearer abc"]) == {"Authorization": "Bearer abc"}


def test_parse_headers_handles_colons_in_value():
    assert _parse_headers(["X-Trace: a:b:c"]) == {"X-Trace": "a:b:c"}


def test_parse_headers_empty():
    assert _parse_headers(None) == {}


@pytest.mark.parametrize("bad", ["no-colon", ": value"])
def test_parse_headers_rejects_malformed(bad):
    with pytest.raises(ValueError):
        _parse_headers([bad])


def test_list_detectors_reports_cwes():
    entries = json.loads(list_detectors())
    assert entries, "detector catalogue should not be empty"
    by_category = {e["category"]: e for e in entries}
    assert by_category["sql_injection"]["cwe"] == "CWE-89"
    assert by_category["xss"]["cwe"] == "CWE-79"
    assert all(e["cwe"].startswith("CWE-") for e in entries)


async def test_scan_target_refuses_unauthorized_remote_host():
    """An agent must not be able to scan a non-loopback host without authorization."""
    out = json.loads(await scan_target("http://example.com", authorized=False))
    assert "error" in out
    assert "authoriz" in out["error"].lower()


async def test_scan_target_rejects_non_http_scheme():
    out = json.loads(await scan_target("ftp://example.com", authorized=True))
    assert "error" in out
