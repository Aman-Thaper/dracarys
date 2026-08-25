# DRACARYS DAST for VS Code

Scan a running application for real, confirmed vulnerabilities without leaving the editor.

**Attack. Prove. Fix. Retest.**

Every DRACARYS finding is confirmed by a **deterministic oracle** plus captured
request/response evidence — a language model never decides what counts as a vulnerability.

## Requirements

The extension drives the DRACARYS CLI, so install that first:

```bash
pipx install dracarys-dast     # or: pip install dracarys-dast
```

If `dracarys` is not on your `PATH`, set `dracarys.executable` to its full path.

## Commands

| Command | What it does |
|---|---|
| **DRACARYS: Scan a target URL** | Crawls the target, runs the detectors, and opens the findings beside your code. |
| **DRACARYS: Open a SARIF report** | Renders a `.sarif` file produced by any DRACARYS run, including one from CI. |

## What it detects

SQL injection (error, boolean, and time based), reflected XSS, IDOR/BOLA, open redirect,
exposed files and secrets, security misconfiguration, verbose error disclosure, and exposed
API schemas — all CWE-mapped, each with remediation guidance.

## Authorization

Loopback targets scan freely. Any other host requires you to confirm, in a modal, that you
are authorized to test it; the CLI enforces the same gate independently. Payloads are
non-destructive by contract: read-only SQL, benign markers, and short sleeps.

**Only scan systems you have permission to test.**

## Settings

| Setting | Default | Purpose |
|---|---|---|
| `dracarys.executable` | `dracarys` | Path to the CLI. |
| `dracarys.target` | `http://127.0.0.1:3000` | URL offered when starting a scan. |
| `dracarys.maxPages` | `60` | Crawl budget. |
| `dracarys.passive` | `false` | Passive checks only — send no injection probes. |

## Scope

An early-stage lightweight DAST: evidence-first, low false positives, SARIF/CI-native.
It is not a Burp or ZAP replacement.

[Source and documentation](https://github.com/Aman-Thaper/dracarys) · MIT licensed
