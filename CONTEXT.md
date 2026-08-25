# DRACARYS — Project Context (start here)

> Durable handoff/context doc. Read this first when resuming work. It captures what
> the project is, how it's built, how to run it, the non-obvious decisions and gotchas,
> and what's left to do. Detailed docs: README, USAGE, ARCHITECTURE, SECURITY, EVALUATION.

_Last updated: 2026-08-25._

---

## 1. What DRACARYS is (one paragraph)

A **generic DAST (dynamic application security testing) scanner** that crawls any
**authorized** HTTP target, runs **generic vulnerability detectors** confirmed by
**deterministic oracles + captured evidence** (the LLM never decides truth), and emits
findings as **SARIF / HTML / JSON / Markdown**. Its differentiator is **verified
remediation**: for a target it can rebuild (the bundled lab, or your app in CI) it
generates a fix, rebuilds the target patched, **replays the original attack, and reports
FIX VERIFIED** only when the exploit actually stops working. Tagline: **Attack. Prove.
Fix. Retest.**

**Honest scope:** a real but **early-stage lightweight DAST** — evidence-first, low false
positives, SARIF/CI-native, plus verified-fix retesting. NOT a Burp/ZAP replacement.

## 2. Status (as of last update)

- ✅ Generic scanner engine + 8 detector classes, proven to generalize.
- ✅ `dracarys scan` CLI (auth gate, safe payloads, severity exit codes, multi-format reports).
- ✅ SARIF 2.1.0 output; GitHub Marketplace **Action** (`action.yml`, Docker) + example workflow.
- ✅ `POST /api/scan` HTTP endpoint.
- ✅ Verified-remediation campaign loop against the bundled DRACARYS BANK lab (attack graph,
  remediation, patched rebuild, retest → FIX VERIFIED).
- ✅ Next.js command center (visual, real-time) for the lab campaign.
- ✅ Quality: **72 tests, ~85% coverage**, `ruff` clean, `mypy` clean (65 files).
  ~7,000 LOC Python + ~880 LOC TypeScript.
- ⛔ NOT done: git not initialized; not published to PyPI or GitHub Marketplace; scanner
  results not yet surfaced in the web UI; no background/async scan jobs; detector coverage
  is the "core 8" (no SSRF/CORS/CSRF/auth-session yet). See §9 Roadmap.

## 3. Environment constraints (IMPORTANT, non-obvious)

This machine has **no Docker, no Postgres server, no Redis, no uv/poetry/pnpm**. The repo
ships `docker-compose.yml` + Dockerfiles as the *documented production path* but **they
cannot run here — do not `docker compose`.** Everything runs self-contained:

- **DB:** async SQLAlchemy on **SQLite** (`DRACARYS_DATABASE_URL` defaults to a local file).
  Swap to Postgres via `postgresql+asyncpg://…` for prod. Enum columns use a custom
  `EnumType` (`db/base.py`) that stores `.value` and rebuilds the enum on load.
- **Lab & patched instances:** the lab is a real FastAPI app driven **in-process** over an
  httpx ASGI transport (real HTTP, no socket). The patched retest instance is a second
  in-process app with the fix flag applied.
- **Orchestration:** campaigns run as asyncio background tasks (a Redis/ARQ worker is the
  documented scale-out path, not required).
- Backend uses the project **venv `.venv`**. Package (distribution) name is **`dracarys-dast`**;
  the **import** package is **`dracarys`**.

## 4. How to run / verify

```bash
make setup                 # venv + editable install (.[dev,llm])
# scanner (the product)
.venv/bin/dracarys scan http://127.0.0.1:3000          # loopback: no auth flag needed
.venv/bin/dracarys scan https://app --yes-i-am-authorized --sarif out.sarif --fail-on high
.venv/bin/dracarys scan-selftest                       # generalization scorecard (recall 1.0, 0 FP)
# verified-remediation loop (bundled lab)
.venv/bin/dracarys demo                                # full attack→prove→fix→retest report
.venv/bin/dracarys eval                                # scored vs ground truth (all 1.0)
# quality gates
.venv/bin/python -m pytest                             # 72 tests
.venv/bin/ruff check dracarys lab tests                # clean
.venv/bin/mypy dracarys                                # clean
# services
make api                                               # FastAPI control plane :8000 (/docs, /api/scan)
make web                                               # Next.js command center :3000 (proxies /api → :8000)
```
Handy Make targets: `demo eval selftest scan URL=… test cov lint fmt typecheck web-build migrate reset`.

## 5. Repo map (where things live)

```
dracarys/
  config.py                  settings (env-driven; safe local defaults)
  cli.py                     `dracarys` CLI: scan · scan-selftest · demo · eval · serve · lab
  domain/                    enums (VulnCategory, Severity, …) + Pydantic API schemas
  db/                        async engine, ORM models, EnumType, TZDateTime  (SQLite/Postgres)
  engine/
    policy/                  Scope + PolicyEngine  ← the safety boundary (scope, budget, kill switch)
    evidence/                hashed, redacted evidence store
    graph/                   attack-graph build + chain discovery (lab)
    orchestrator/            campaign state machine, lab controller, the loop, retest
  tools/                     typed HTTP tool (execute(spec) + send(absolute_url))
  agents/                    recon, planner (heuristic + LLM), attack modules, remediation (lab)
  llm/                       provider-agnostic LLM (Anthropic + mock)  — planning only, never validation
  scanner/                   ★ THE PRODUCT ★  generic DAST engine
    crawler.py               links/forms/params + OpenAPI import → RequestTemplates + baselines
    oracles.py               deterministic signals (SQL errors, boolean divergence, timing, reflection, secrets)
    detectors/
      passive.py             headers, secrets, verbose/DB errors        (response detectors)
      injection.py           SQLi (error/boolean/time), XSS, open redirect (param detectors)
      exposure.py            exposed files/secrets, API schema           (site detectors)
      access.py              IDOR/BOLA differential (needs 2 identities) (site detector)
      base.py                detector protocols + request helpers (make_finding, mutate, send_template)
    engine.py                Scanner: crawl → passive → active → site → dedupe/rank
    report.py                to_json / to_sarif / to_markdown / to_html
    runner.py                authorize() gate + build a live-network scanner (shared by CLI & API)
    testbed.py               built-in independent vulnerable apps (blog/api) + hardened "safe" control + ground truth
    models.py                RequestTemplate, ScanFinding, ScanConfig, ScanResult
    cwe.py                   CWE ids + generic remediation text per class
  api/                       FastAPI app + service + routes (health, targets, campaigns, resources,
                             audit, metrics, scan) ; /api/scan runs the scanner
  evaluation/                harness.py (lab campaign scoring) + scanner_eval.py (generalization)
lab/                         DRACARYS BANK — deliberately vulnerable target + ground truth + seed (in-process)
web/                         Next.js 14 command center (TS + Tailwind), proxies /api to backend
tests/                       unit · integration · e2e · evaluation
alembic/                     migrations (0001 initial = create_all from metadata)
infra/docker/                Dockerfiles (api, web, action) + entrypoints  (documented prod path)
action.yml                   GitHub Marketplace Action (Docker) → SARIF
.github/workflows/           ci.yml (lint/test/eval/selftest) + example-dast.yml (consumer template)
docs/ + *.md                 README, USAGE, ARCHITECTURE, SECURITY, EVALUATION, DEVELOPMENT, API, CHANGELOG, LICENSE
```

## 6. Architecture in brief

- **Scanner path:** `Scanner.scan()` → crawl (+OpenAPI) → passive detectors on every
  response → active detectors mutate each injection point → site detectors → dedupe/rank →
  reporters. Every finding cites a deterministic oracle + paired baseline/attack exchanges.
- **Safety path (all HTTP):** planner/detector → **typed** tool request → `PolicyEngine.guard(url)`
  (scheme, no creds-in-url, host allowlist, port allowlist, private/loopback resolution,
  budget, concurrency, timeout, kill switch) → bounded httpx → evidence (auth/cookies redacted).
- **Verified remediation (lab):** campaign state machine CREATED→…→COMPLETE; the same attack
  modules run against the vulnerable app (CONFIRMED) and the patched instance (must become
  DISPROVEN) → FIX VERIFIED. Resumable dispatcher (pause/resume/stop).
- **LLM:** pluggable planner only (`HeuristicPlanner` default offline; `LLMPlanner`/Anthropic
  optional). Validation is ALWAYS deterministic Python — the model can never assert a vuln.

## 7. Detectors & oracles (current coverage)

| Class | CWE | Oracle |
|---|---|---|
| SQL injection | CWE-89 | DB error signature (absent in baseline) · boolean TRUE≈baseline & FALSE diverges (multi-context payloads incl. `LIKE '%..%'`) · time sleep dominates a control |
| Reflected XSS | CWE-79 | unique HTML payload reflected **unencoded** in a `text/html` response |
| IDOR / BOLA | CWE-639 | 2nd identity fetches another user's object with content ≈ owner's (needs `--second-auth` + `--protected-url`) |
| Open redirect | CWE-601 | redirect-ish param drives a 30x `Location` to an attacker host (params inspected only) |
| Exposed files/secrets | CWE-538/200 | sensitive path returns recognizable content, or a body matches a secret regex (AWS/JWT/GH/Stripe/private keys/…) |
| Security misconfig | CWE-16 | missing CSP/HSTS/X-Content-Type-Options/X-Frame-Options/Referrer-Policy; version disclosure |
| Verbose/info disclosure | CWE-209/200 | stack traces / DB error text in normal responses |
| Exposed API schema | CWE-200 | `/openapi.json` etc. served publicly |

Testbed proof: blog app (HTML) + api app (JSON) — **recall 1.0 (10/10)**, **0 false positives**
on the hardened `safe` app. Gated by `dracarys scan-selftest` and `tests/integration/test_scanner.py`.

## 8. Key decisions & gotchas (save future-you time)

- **Enum columns:** must use `EnumType(SomeEnum)` in `db/models.py` (not raw `String`) or they
  read back as plain strings. Already applied everywhere.
- **In-memory SQLite is NOT shared** across the orchestrator's many async sessions → tests use
  **file-backed temp SQLite** (`tmp_path`). The scanner/lab tests use httpx `ASGITransport`.
- **mypy trap — variable reuse across loops:** reusing one loop var name (`gt`, `det`) across
  loops of different types breaks mypy AND once caused a real bug (attack-graph REACHES edge
  pointed at a stale node). Use distinct names per loop. Bit us twice.
- **Boolean SQLi needs context-aware payloads** (string, `LIKE '%..%'` with comment, numeric)
  and a **seed value that returns rows** (OpenAPI default/example is extracted for this).
- **Passive detectors also run on active-baseline responses** so API-only endpoints (no crawl
  link) are still scanned for secrets/errors.
- **Authorization gate** (`scanner/runner.authorize`): loopback allowed; non-loopback refused
  without `--yes-i-am-authorized` / `authorized:true` / `DRACARYS_AUTHORIZED=1`. For authorized
  external scans the scope's private-IP check is relaxed (the allowlist is the control).
- **Payloads are non-destructive** by contract (read-only SQL, benign markers, short sleeps,
  OOB host never contacted). Keep it that way when adding detectors.
- **Frontend:** if `next start` shows "Cannot find module './819.js'", the `.next` build is
  stale → `rm -rf web/.next && npm run build`. Page is a client component; static export is fine.
- **Package name** is `dracarys-dast` (PyPI) but you still `import dracarys` and run `dracarys`.
- **Playwright** was used once to visually verify the UI, then uninstalled — devDeps are lean.

## 9. Roadmap / next steps (pick up here)

**To actually ship (needs the owner's accounts — I can't do these):**
1. `git init` + clean first commit (repo is NOT a git repo yet) + tag `v0`.
2. Publish `dracarys-dast` to PyPI (`python -m build && twine upload`; needs token).
3. Publish the Action to GitHub Marketplace (push repo, release, submit `action.yml`).

**Product depth (safe, high-value next):**
4. More detectors: SSRF (OOB callback), CORS misconfig, CSRF token checks, auth/session
   weaknesses, verbose-JSON PII, path traversal, SSTI. Each = oracle + testbed case + test.
5. Background/async scan jobs + a `Scan`/`ScanFinding` persistence model (currently `/api/scan`
   is synchronous) so large scans and history work; surface scans in the web UI.
6. Wire arbitrary (non-lab) targets into the campaign so scanner findings flow into the
   attack-graph + verified-remediation where the target is rebuildable (CI use case).
7. Broaden crawler (JS-rendered apps via optional Playwright; auth login flows; sitemaps).
8. Observability: OpenTelemetry spans around scans; Prometheus `/metrics` already exists as JSON.

**Honesty guardrail:** keep every finding backed by a deterministic oracle + evidence, keep
false positives on the `safe` control at 0, and never add destructive payloads.

## 10. Config surface (env, all optional; safe defaults)

`DRACARYS_DATABASE_URL` · `DRACARYS_API_HOST/PORT` · `DRACARYS_LAB_HOST/PORT/PATCHED_PORT` ·
`DRACARYS_SCOPE_ALLOWLIST` · `DRACARYS_SCOPE_ALLOWED_PORTS` · `DRACARYS_MAX_REQUESTS_PER_CAMPAIGN`
· `DRACARYS_MAX_CONCURRENCY` · `DRACARYS_TOOL_TIMEOUT_SECONDS` · `DRACARYS_LLM_PROVIDER`
(`heuristic`|`anthropic`) · `DRACARYS_ANTHROPIC_API_KEY` · `DRACARYS_AUTHORIZED` (scan gate).
See `.env.example`.
