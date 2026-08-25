# DRACARYS — Usage

## Install
```bash
pipx install dracarys-dast        # recommended (isolated)
# or
pip install dracarys-dast
# or from source
make setup                        # creates .venv and installs the package
```

## `dracarys scan` — the scanner

```
dracarys scan URL [options]
```

| Option | Description | Default |
|---|---|---|
| `URL` | Target base URL (e.g. `https://app.example.com`) | — |
| `--yes-i-am-authorized` | Required to scan a non-loopback target | off |
| `--passive` | Passive checks only; no active injection | active on |
| `--no-time` | Disable time-based SQLi probes | time on |
| `--auth 'Name: value'` | Auth header for the scanner (repeatable) | — |
| `--second-auth 'Name: value'` | Second identity header for IDOR testing (repeatable) | — |
| `--protected-url URL` | A URL owned by the second identity (repeatable, for IDOR) | — |
| `--scope HOST` | Additional in-scope host (repeatable) | target host |
| `--max-pages N` | Max pages to crawl | 60 |
| `--max-requests N` | Hard request budget for the scan | 3000 |
| `--format {table,json,sarif,md,html}` | Primary output to stdout/`--out` | table |
| `--out FILE` | Write the primary format to a file | — |
| `--sarif/--md/--html/--json FILE` | Also write that format from the same scan | — |
| `--fail-on {critical,high,medium,low,none}` | Non-zero exit if a finding at/above this severity exists | high |

### Examples

```bash
# Local app, human-readable table
dracarys scan http://127.0.0.1:3000

# Authenticated scan of an authorized target, multiple reports at once
dracarys scan https://staging.example.com \
  --yes-i-am-authorized \
  --auth "Authorization: Bearer $TOKEN" \
  --sarif dracarys.sarif --html report.html --md report.md \
  --fail-on high

# IDOR / broken access control (two identities)
dracarys scan https://api.example.com --yes-i-am-authorized \
  --auth "Authorization: Bearer $USER1" \
  --second-auth "Authorization: Bearer $USER2" \
  --protected-url https://api.example.com/api/orders/1001

# Production-safe passive posture check (no injection)
dracarys scan https://example.com --yes-i-am-authorized --passive --fail-on none
```

### What it detects
SQL injection (error/boolean/time), reflected XSS, IDOR/BOLA (with two identities),
open redirect, exposed files & secrets (`.env`, `.git`, keys, tokens, JWTs, DB dumps,
actuator), missing security headers, verbose errors / DB error disclosure, and exposed
API schemas. Every finding is CWE-mapped and carries request/response evidence.

## `dracarys scan-selftest` — prove it generalizes
```bash
dracarys scan-selftest
```
Scans built-in, independent vulnerable apps and scores detection recall + false positives
against a hardened control. Exits non-zero on regression — useful as a CI gate on the tool
itself.

## GitHub Action
`action.yml` (Docker-based). Inputs: `target`, `fail-on`, `passive`, `auth-header`,
`authorized`, `sarif-file`, `max-pages`. Output: `sarif-file`. See
[`.github/workflows/example-dast.yml`](.github/workflows/example-dast.yml) for a full
pipeline that starts your app, scans it, and uploads SARIF to the Security tab.

## HTTP API
```bash
make api    # http://127.0.0.1:8000
curl -s http://127.0.0.1:8000/api/scan -H 'content-type: application/json' \
  -d '{"url":"http://127.0.0.1:3000","active":true}' | jq '.findings[].title'
```
Body: `{ url, active, include_time_based, max_pages, max_requests, auth_headers, authorized }`.
Non-loopback targets require `"authorized": true`.

## Verified remediation (rebuildable targets)
For a target DRACARYS can rebuild patched — the bundled lab, or your app wired into a
campaign — it generates a fix, launches a patched instance, replays the original attack,
and reports **FIX VERIFIED / FIX FAILED**. Try it end to end:
```bash
make demo     # full attack → prove → fix → retest against the bundled lab
make eval     # scored against ground truth
```

## Exit codes
`0` clean (or below `--fail-on`), `1` findings at/above threshold, `2` bad input / refused
(e.g. scanning a non-loopback target without `--yes-i-am-authorized`).
