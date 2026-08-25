"""Deterministic oracles — the honest heart of the scanner.

Each oracle turns a raw response comparison into a yes/no signal a detector can
cite as evidence. No oracle relies on a model's opinion; they are string/timing/
statistical tests over real captured responses.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

from dracarys.tools.base import HttpExchange

# --- SQL error signatures across common engines --------------------------
SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySqlException",
    r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"pg_exec\(\)", r"PSQLException",
    r"unterminated quoted string at or near", r"syntax error at or near",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"sqlite3\.OperationalError", r"SQLITE_ERROR", r"unrecognized token:",
    r"near \".*\": syntax error", r"no such column",
    r"Microsoft SQL Server", r"ODBC SQL Server Driver", r"SQLServerException",
    r"Unclosed quotation mark after the character string",
    r"ORA-[0-9]{5}", r"Oracle error", r"quoted string not properly terminated",
]
_SQL_RE = re.compile("|".join(SQL_ERRORS), re.IGNORECASE)

# --- stack-trace / debug signatures --------------------------------------
STACK_TRACES = [
    r"Traceback \(most recent call last\)", r"File \".*\", line \d+, in ",
    r"at [\w.$]+\([\w.]+\.java:\d+\)", r"Exception in thread",
    r"System\.NullReferenceException", r"org\.springframework",
    r"Werkzeug Debugger", r"DEBUG = True", r"Whitespace at",
    r"<b>Fatal error</b>", r"<b>Warning</b>:.*on line",
]
_STACK_RE = re.compile("|".join(STACK_TRACES), re.IGNORECASE)

# --- secret patterns (sensitive data exposure) ---------------------------
SECRET_PATTERNS: list[tuple[str, str]] = [
    ("AWS access key id", r"AKIA[0-9A-Z]{16}"),
    ("AWS secret access key", r"(?i)aws.{0,20}?(secret|access).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
    ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("Private key block", r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("JSON Web Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("GitHub token", r"gh[posru]_[0-9A-Za-z]{36}"),
    ("Stripe secret key", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Generic password field", r"(?i)\"?password\"?\s*[:=]\s*\"[^\"]{4,}\""),
]


def sql_error_signature(text: str) -> str | None:
    m = _SQL_RE.search(text or "")
    return m.group(0) if m else None


def stack_trace_signature(text: str) -> str | None:
    m = _STACK_RE.search(text or "")
    return m.group(0) if m else None


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return (label, matched-substring) pairs for any secrets found."""
    out: list[tuple[str, str]] = []
    for label, pat in SECRET_PATTERNS:
        m = re.search(pat, text or "")
        if m:
            snippet = m.group(0)
            out.append((label, snippet[:12] + "…" if len(snippet) > 14 else snippet))
    return out


def reflects_unencoded(marker: str, exchange: HttpExchange) -> bool:
    """True if the raw (HTML-dangerous) marker appears unencoded in an HTML body."""
    ct = (exchange.response.get("headers", {}) or {}).get("content-type", "")
    if "html" not in ct.lower():
        return False
    body = exchange.body_text
    # If our angle-bracket payload survived without entity-encoding, it is injectable.
    return marker in body and marker.replace("<", "&lt;") not in body


def similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    return SequenceMatcher(None, a or "", b or "").quick_ratio()


def boolean_divergence(base: HttpExchange, truthy: HttpExchange, falsy: HttpExchange) -> bool:
    """Boolean-based SQLi oracle.

    A TRUE condition should resemble the baseline while a FALSE condition should
    diverge — the hallmark of the parameter influencing the query logic.
    """
    if truthy.status_code is None or falsy.status_code is None:
        return False
    sim_true = similarity(base.body_text, truthy.body_text)
    sim_false = similarity(base.body_text, falsy.body_text)
    diff_tf = similarity(truthy.body_text, falsy.body_text)
    # TRUE close to baseline, FALSE clearly different from both baseline and TRUE.
    return sim_true >= 0.95 and sim_false <= 0.9 and diff_tf <= 0.9 and (sim_true - sim_false) >= 0.05


def time_delayed(control_ms: int, test_ms: int, injected_seconds: float) -> bool:
    """Time-based oracle: the injected sleep must clearly dominate the control."""
    threshold = injected_seconds * 1000 * 0.7
    return (test_ms - control_ms) >= threshold and test_ms >= injected_seconds * 1000 * 0.7


MISSING_HEADER_CHECKS = [
    ("content-security-policy", "Content-Security-Policy", "medium"),
    ("x-content-type-options", "X-Content-Type-Options", "low"),
    ("x-frame-options", "X-Frame-Options", "low"),
    ("strict-transport-security", "Strict-Transport-Security", "medium"),
    ("referrer-policy", "Referrer-Policy", "info"),
]
