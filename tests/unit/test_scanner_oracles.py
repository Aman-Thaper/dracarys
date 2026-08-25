"""Unit tests for the deterministic scanner oracles."""
from dracarys.scanner.oracles import (
    boolean_divergence,
    find_secrets,
    reflects_unencoded,
    sql_error_signature,
    stack_trace_signature,
    time_delayed,
)
from dracarys.tools.base import HttpExchange, ToolStatus


def _ex(body="", status=200, ctype="text/html", elapsed=10):
    return HttpExchange(
        status=ToolStatus.OK, body_text=body,
        response={"status_code": status, "headers": {"content-type": ctype}},
        elapsed_ms=elapsed,
    )


def test_sql_error_signatures():
    assert sql_error_signature("near \"x\": syntax error")
    assert sql_error_signature("You have an error in your SQL syntax near MySQL")
    assert sql_error_signature("PostgreSQL query failed: ERROR")
    assert sql_error_signature("totally normal response") is None


def test_secret_detection():
    assert any("AWS" in lbl for lbl, _ in find_secrets("id=AKIAIOSFODNN7EXAMPLE"))
    assert any("JSON Web Token" in lbl for lbl, _ in find_secrets(
        "t=eyJhbGciOiJIUzI1NiJ9.eyJ1IjoiYSJ9.c2lnbmF0dXJlc2FtcGxlMTIzNDU2"))
    assert find_secrets("nothing to see") == []


def test_stack_trace():
    assert stack_trace_signature("Traceback (most recent call last): ...")
    assert stack_trace_signature("all good") is None


def test_reflects_unencoded_only_in_html():
    marker = "dcrsXYZ<svg/onload=1>"
    assert reflects_unencoded(marker, _ex(body=f"hello {marker} world"))
    # encoded reflection is NOT a finding
    assert not reflects_unencoded(marker, _ex(body="hello dcrsXYZ&lt;svg/onload=1&gt;"))
    # JSON reflection is not XSS
    assert not reflects_unencoded(marker, _ex(body=marker, ctype="application/json"))


def test_boolean_divergence():
    base = _ex(body="rows: apple, apricot")
    truthy = _ex(body="rows: apple, apricot")     # same as baseline
    falsy = _ex(body="rows:")                       # empty
    assert boolean_divergence(base, truthy, falsy)
    # no divergence when all identical
    assert not boolean_divergence(base, base, base)


def test_time_delayed():
    assert time_delayed(20, 3100, 3)       # ~3s delay over 20ms control
    assert not time_delayed(20, 60, 3)     # fast response, no delay
