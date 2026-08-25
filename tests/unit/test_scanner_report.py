"""Unit tests for scan reporters and the authorization gate."""
import json

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, Severity, VulnCategory
from dracarys.scanner.models import ScanFinding, ScanResult
from dracarys.scanner.report import to_html, to_json, to_markdown, to_sarif
from dracarys.scanner.runner import authorize
from dracarys.tools.base import HttpExchange, ToolStatus


def _result():
    ex = HttpExchange(status=ToolStatus.OK, body_text="proof",
                      request={"method": "GET", "url": "http://t/x?id=1'"},
                      response={"status_code": 500})
    f = ScanFinding(
        detector="sqli", category=VulnCategory.SQL_INJECTION, severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED, title="SQL injection in 'id'", url="http://t/x",
        method="GET", detail="db error", cwe="CWE-89", remediation="parameterize",
        param="id", evidence=[LabeledExchange("injection", ex)],
    ).finalize()
    return ScanResult(base_url="http://t", findings=[f], pages_crawled=2, requests_made=9)


def test_sarif_is_valid():
    doc = json.loads(to_sarif(_result()))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "DRACARYS"
    assert run["results"][0]["ruleId"] == "sql_injection"
    assert run["results"][0]["level"] == "error"
    assert run["results"][0]["properties"]["cwe"] == "CWE-89"


def test_json_and_markdown_and_html():
    r = _result()
    doc = json.loads(to_json(r))
    assert doc["findings"][0]["cwe"] == "CWE-89"
    assert doc["severity_breakdown"]["critical"] == 1
    md = to_markdown(r)
    assert "CWE-89" in md and "SQL injection" in md
    html = to_html(r)
    assert "DRACARYS scan report" in html and "SQL injection" in html


def test_authorization_gate():
    assert authorize("http://127.0.0.1:8888/", False).ok       # loopback allowed
    assert not authorize("https://example.com/", False).ok      # external needs consent
    assert authorize("https://example.com/", True).ok           # explicit authorization
    assert not authorize("ftp://x/", True).ok                   # bad scheme
