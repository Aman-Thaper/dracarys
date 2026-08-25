<div align="center">

# 🐉 DRACARYS

### ATTACK. PROVE. FIX. RETEST.

**An autonomous DAST scanner that finds real web vulnerabilities in any authorized
target, proves each one with deterministic evidence, and — for targets you can
rebuild — verifies the fix by replaying the original attack.**

`dracarys scan https://your-app` · SARIF for GitHub code scanning · GitHub Action · CLI · API

</div>

---

## What it is

DRACARYS is a **dynamic application security testing (DAST)** tool. Point it at an
authorized HTTP target and it will:

1. **Crawl** the site (links, forms, query params) and **import an OpenAPI schema** if one is exposed.
2. Run **generic detectors** against the discovered surface — not signatures tied to one app.
3. **Confirm** every finding with a **deterministic oracle** and capture the request/response as **evidence** — the model never decides that something is vulnerable.
4. Emit findings as **SARIF** (GitHub Security tab), **HTML**, **JSON**, or **Markdown**.

Detected classes today: **SQL injection** (error / boolean / time based), **reflected XSS**,
**broken object-level authorization (IDOR)**, **open redirect**, **exposed files & secrets**
(`.env`, `.git`, keys, tokens, JWTs), **security misconfiguration** (missing headers),
**verbose errors / info disclosure**, and **exposed API schemas**. `CWE`-mapped.

### The differentiator: verified remediation

Most scanners stop at "found." DRACARYS can go further when the target is one you can
rebuild (your app in CI, or the bundled lab): it generates a fix, **rebuilds the target
patched, replays the exact original attack, and reports FIX VERIFIED only when the
exploit genuinely stops working.** That closed loop — attack → prove → fix → retest — is
what the name is about.

## Is it real, or a demo?

Real — and it ships with the proof. The detectors are validated against **independent
apps they were never written for**:

```bash
dracarys scan-selftest
# recall 1.0 (10/10 vuln classes across two different apps) · 0 false positives on a hardened control · PASS ✓
```

Honest scope: DRACARYS is a focused, safe, evidence-first **lightweight DAST** — not a
Burp/ZAP replacement. Its edges are (a) deterministic, evidence-backed findings with low
false positives, (b) first-class SARIF/CI integration, and (c) verified-fix retesting.

## Install

```bash
pipx install dracarys-dast          # or: pip install dracarys-dast
pip install "dracarys-dast[mcp]"    # + the MCP server, for agent clients
# from source:
git clone https://github.com/Aman-Thaper/dracarys && cd dracarys && make setup
```

## Use it

### CLI

```bash
# Scan a local app (loopback needs no authorization flag)
dracarys scan http://127.0.0.1:3000

# Scan an authorized remote target, write SARIF + HTML, fail CI on high+ findings
dracarys scan https://staging.example.com \
  --yes-i-am-authorized \
  --auth "Authorization: Bearer $TOKEN" \
  --sarif dracarys.sarif --html report.html --fail-on high

# Passive-only (no active injection), e.g. for production smoke checks
dracarys scan https://example.com --yes-i-am-authorized --passive
```

Exit code is non-zero when a finding at/above `--fail-on` is present, so it gates CI.
See [USAGE.md](USAGE.md) for every flag, auth/IDOR options, and output formats.

### GitHub Action (marketplace)

Run DRACARYS against your app in CI and publish findings to the **Security** tab:

```yaml
permissions: { contents: read, security-events: write }
jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      # ...start your app so it's reachable at http://localhost:3000...
      - id: scan
        uses: Aman-Thaper/dracarys@v0
        with:
          target: http://localhost:3000
          fail-on: high
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: "${{ steps.scan.outputs.sarif-file }}" }
```

A ready-to-copy workflow is in [`.github/workflows/example-dast.yml`](.github/workflows/example-dast.yml).

### MCP server (agent clients)

Expose DRACARYS to any MCP-capable agent (Claude Code, Claude Desktop, …) over stdio:

```bash
pip install "dracarys-dast[mcp]"
dracarys-mcp
```

Register it with Claude Code:

```bash
claude mcp add dracarys -- dracarys-mcp
```

Tools: `scan_target` (run a scan, return findings) and `list_detectors` (the CWE-mapped
catalogue). The same authorization gate applies — a non-loopback target requires
`authorized=true`, so an agent cannot point the scanner at an arbitrary host on its own.

### API / hosted

```bash
make api    # POST /api/scan {"url": "...", "authorized": true, "auth_headers": {...}}
```

### The command center (visual)

```bash
make api && make web     # http://localhost:3000 — watch a full attack→prove→fix→retest run
```

## Safety & authorization (read this)

DRACARYS performs active security tests. It is engineered to stay inside the lines:

- **Authorization gate:** scanning any non-loopback target requires `--yes-i-am-authorized`
  (or `DRACARYS_AUTHORIZED=1`). Loopback is allowed for your own machine.
- **Scope enforcement:** requests are confined to the target host/port allowlist; the
  policy engine blocks anything else before it hits the network.
- **Non-destructive by default:** read-only SQL payloads, benign XSS markers, short sleeps;
  no `DROP`/`DELETE`/`UPDATE`, no stored payloads. Active tests are opt-out (`--passive`).
- **Bounded:** per-scan request budget, concurrency limit, per-request timeout, kill switch.
- **Evidence redaction:** `Authorization`/`Cookie` headers are redacted in stored evidence.

Only scan systems you own or are explicitly authorized to test. See [SECURITY.md](SECURITY.md).

## How findings stay honest

Each detector cites a **deterministic oracle**, not an opinion:

| Class | Oracle |
|---|---|
| SQL injection | DB error signature appears where the baseline had none; or a TRUE condition matches the baseline while a FALSE one diverges; or an injected sleep dominates a control request |
| Reflected XSS | a unique HTML payload is reflected **unencoded** in an `text/html` response |
| IDOR / BOLA | a second identity retrieves another user's object with content equivalent to the owner's |
| Open redirect | a param drives a 30x `Location` to an attacker-controlled host |
| Exposed files / secrets | a sensitive path returns recognizable content, or a response matches a secret pattern |

Findings carry the paired baseline/attack exchanges (with SHA-256 fingerprints) as proof.

## Documentation

- **[CONTEXT.md](CONTEXT.md) — start here: full project context, status, decisions, and roadmap**
- [USAGE.md](USAGE.md) — CLI, Action, API, auth, output formats, CI recipes
- [ARCHITECTURE.md](ARCHITECTURE.md) — scanner engine, detectors, campaign loop, verified retest
- [SECURITY.md](SECURITY.md) — authorization/isolation model and responsible use
- [EVALUATION.md](EVALUATION.md) — the generalization scorecard and methodology
- [DEVELOPMENT.md](DEVELOPMENT.md) — setup, layout, adding a detector
- [API.md](API.md) — REST surface · [docs/demo.md](docs/demo.md) — the guided demo

## Tech

Python 3.12 · FastAPI · Pydantic v2 · SQLAlchemy 2 (async) · httpx · structlog · pytest ·
Next.js 14 · TypeScript · Tailwind · Docker · GitHub Actions · SARIF 2.1.0.

## License

MIT — see [LICENSE](LICENSE).

---

<div align="center"><b>DRACARYS</b> — Attack. Prove. Fix. Retest.</div>
