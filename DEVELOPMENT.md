# DRACARYS — Development Guide

## Prerequisites
- Python 3.11+ (3.12 recommended)
- Node 18+ (for the frontend)
- No Docker/Postgres/Redis required for local dev — SQLite + in-process lab are the defaults.

## Setup
```bash
make setup       # venv + backend (editable) + dev + llm extras
make web-setup   # frontend deps (only needed for the UI)
cp .env.example .env   # optional; safe defaults work without it
```

## Everyday commands
```bash
make demo        # run a full campaign headless, print the report
make eval        # run a campaign and score it against ground truth
make test        # full test suite (unit + integration + e2e + evaluation)
make cov         # tests with coverage
make lint        # ruff
make fmt         # ruff --fix + format
make typecheck   # mypy on the platform package
make api         # run the control-plane API (:8000, --reload)
make web         # run the command center (:3000)
make lab-up      # run the vulnerable lab as its own service (:8888)
make migrate     # alembic upgrade head
make reset       # remove local db + caches
```

## Project layout
```
dracarys/
  config.py            settings (env-driven, safe defaults)
  logging.py           structlog setup
  domain/              enums + Pydantic API schemas
  db/                  async engine, models, EnumType, TZDateTime
  engine/
    policy/            Scope + PolicyEngine (safety boundary)
    evidence/          hashed evidence store
    graph/             attack-graph build + chain discovery
    orchestrator/      state machine, lab controller, the loop
  tools/               typed HTTP tool + contracts
  agents/              recon, planner, attack modules, remediation, context
  llm/                 provider protocol, Anthropic provider, mock
  api/                 FastAPI app, service, routes, deps
  evaluation/          scoring harness
  cli.py               `dracarys` CLI (serve|lab|demo|eval)
lab/                   DRACARYS BANK app + ground truth + seed
web/                   Next.js command center
tests/                 unit · integration · e2e · evaluation
alembic/               migrations
infra/docker/          Dockerfiles (api, web) + entrypoints
Dockerfile             GitHub Action image (root-named, required by action.yml)
```

## Adding a vulnerability (and keeping the loop honest)
1. Add the vulnerable + patched code paths in `lab/app.py`, gated by a `LAB-XXX-001` flag.
2. Register ground truth in `lab/ground_truth.py`.
3. Write an `AttackModule` in `dracarys/agents/attacks.py` with an **explicit deterministic
   success criterion** and evidence capture; declare its `depends_on`.
4. Add a planner rule (`agents/planner.py`) and/or catalogue entry (`agents/llm_planner.py`).
5. Add a remediation (`agents/remediation.py`) with a real patch diff and verification test.
6. Add tests: a ground-truth test (vulnerable + patched) and assert the module confirms
   then flips to disproven when patched.

The retest engine and evaluation harness pick up new modules automatically.

## Testing notes
- `asyncio_mode = auto` — async tests need no decorator.
- The in-process lab controller drives lab apps over an ASGI transport, so e2e tests are
  fast and hermetic while still exercising real HTTP + the full policy path.
- Tests use temporary SQLite files (in-memory SQLite is not shared across the
  orchestrator's sessions, so file-backed temp DBs are used).

## Conventions
- Strong typing, explicit error handling, small modules with clear boundaries.
- `ruff` is the linter/formatter; `str, Enum` is intentional (portable JSON/DB values).
- Never log secrets; the policy layer avoids passing secret material into log events.

## Adding a detector (scanner)
Detectors live in `dracarys/scanner/detectors/` and come in three shapes:

- **Response (passive)** — `inspect(url, exchange, ctx) -> [ScanFinding]` (e.g. headers, secrets).
- **Param (active)** — `async probe(template, point, baseline, ctx) -> [ScanFinding]` (e.g. SQLi, XSS).
- **Site** — `async run(ctx) -> [ScanFinding]` (e.g. exposed files, IDOR).

Steps:
1. Implement the detector; confirm findings with a **deterministic oracle** in
   `scanner/oracles.py` and attach the paired baseline/attack exchanges as evidence.
2. Register it in the relevant list in `scanner/detectors/*.py` (picked up automatically).
3. Add a vulnerable case to `dracarys/scanner/testbed.py` and its ground truth, then
   assert detection in `tests/integration/test_scanner.py`. Keep the hardened `safe` app
   clean so `test_safe_app_no_false_positives` guards precision.
4. `make selftest` must still report recall ≥ 0.95 and 0 false positives.

Keep payloads **non-destructive** (read-only, benign markers, short sleeps).
