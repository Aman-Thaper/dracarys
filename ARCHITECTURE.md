# DRACARYS — Architecture

DRACARYS is an autonomous, controlled red-team platform. It drives a persisted
campaign through a fixed lifecycle, using a planner to choose bounded typed tools,
a deterministic engine to validate findings against real evidence, a graph engine
to chain findings into attack paths, and a retest engine to prove fixes by replay.

## Design principles

1. **Evidence over assertion.** A finding is created only when a deterministic
   criterion is satisfied against captured tool output. The model never asserts a
   vulnerability; it only proposes what to try.
2. **The database is the source of truth.** Campaign state, observations, findings,
   evidence, graph, remediations and retests are all persisted. Progress is
   inspectable at any moment and survives a restart.
3. **Contain the offense.** The planner selects *typed* tools; every tool call is
   scope-checked, bounded, and audited. No shell, no arbitrary execution.
4. **Provider-agnostic intelligence.** Planning is pluggable (heuristic or LLM).
   Validation is identical either way.
5. **Prove the fix.** Remediation is only trustworthy if the *original* attack,
   replayed against a freshly patched instance, fails.

## Environment note (why no Docker is required to run it)

The reference stack is Postgres + Redis + Docker. To make the whole loop runnable
and testable with zero infrastructure, DRACARYS also ships a **self-contained mode**:

- **Database:** SQLAlchemy 2.0 async with SQLite by default; set
  `DRACARYS_DATABASE_URL=postgresql+asyncpg://…` for production. Models are portable.
- **Target/patched environments:** the lab is a real FastAPI app. In-process mode
  drives it over an ASGI transport (real HTTP request/response, no socket); live mode
  runs it as a uvicorn process. The patched instance for retest is a genuinely
  disposable second instance built with the relevant fix applied.
- **Orchestration:** the campaign runs as an asyncio task behind a `TaskRunner`-shaped
  seam; a Redis/ARQ worker is the documented scale-out path but is not required.

These are honest substitutions, not simulations: the vulnerabilities are real code
paths, the attacks are real HTTP, and validation is deterministic.

## Component map

```
Planner (heuristic | LLM)  ─┐
                            ├─▶ Orchestrator ─▶ Typed Tools ─▶ Policy/Scope ─▶ Target (lab)
Attack Modules (validators)─┘        │                                   │
                                     ├─▶ Evidence Store (hashed)  ◀──────┘
                                     ├─▶ Attack Graph + Chain discovery
                                     ├─▶ Remediation Agent
                                     └─▶ Retest Engine ─▶ Patched Target (disposable)
```

### Policy / scope engine (`engine/policy`)
- `Scope` = allowlisted hosts + ports. `validate_url` enforces scheme, no embedded
  credentials, host allowlist, port allowlist, **and** that the host resolves to a
  private/loopback range.
- `PolicyEngine` binds scope + per-campaign request budget + concurrency semaphore +
  per-call timeout + a kill switch. Every tool call goes through `guard()`.

### Typed tools (`tools`)
- `HttpRequestSpec` / `HttpExchange` are validated Pydantic contracts.
- `HttpTool` executes a bounded HTTP request through the policy guard and captures a
  complete, hashable exchange. Sensitive headers are redacted in stored evidence.

### Agents (`agents`)
- **Recon** probes a candidate wordlist, classifies endpoints and auth boundaries,
  and flags disclosure — producing structured observations.
- **Planner** turns observations into prioritized hypotheses mapped to attack modules.
  `HeuristicPlanner` is deterministic and offline; `LLMPlanner` uses a provider and
  validates structured output, falling back to heuristic on any error.
- **Attack modules** each perform a bounded exploit *and* apply an explicit success
  criterion, returning `CONFIRMED | DISPROVEN | INCONCLUSIVE` with evidence. They read
  and write an `AttackContext` so discovered artifacts (leaked creds, tokens, the
  canary) flow from one step to the next — this is how a chain forms from real behavior.
- **Remediation** maps a finding to a root cause, recommendation, real patch diff, a
  patch reference (applied to build the patched instance), and a verification test.

### Engine (`engine`)
- **Evidence store** persists exchanges as immutable records with a SHA-256 fingerprint
  and provenance backlinks.
- **Attack graph** builds nodes (asset, endpoint, vulnerability, identity, resource) and
  edges (`discovers`, `exposes`, `authenticates_as`, `enables`, `reaches`) from
  confirmed findings + runtime causality, then discovers directed chains to the canary.
- **Orchestrator** is a resumable state dispatcher: it maps the current persisted state
  to the next phase, honoring pause/stop between phases and the kill switch mid-phase.

## Domain model (persisted)

`Target · Campaign · Asset · Observation · Hypothesis · TestRun · Finding · Evidence ·
AttackPath · GraphNode · GraphEdge · Remediation · Retest · AuditEvent`

Enums are stored as their string value and reconstructed on load (`EnumType`), so the
DB is portable across SQLite and Postgres while the codebase always sees real enums.

## Campaign lifecycle (state machine)

```
CREATED → SCOPING → RECON → ATTACK_PLANNING → TESTING → VALIDATION
        → ATTACK_CHAIN_ANALYSIS → REPORTING → REMEDIATION → RETEST → COMPLETE
control: PAUSED (resumable) · CANCELLED (kill switch) · FAILED (e.g. out of scope)
```

Each phase reloads state, does bounded work, writes its results, and advances. The
dispatcher maps a completed state to the next phase, so **resume** continues exactly
where a pause left off without repeating work.

## The autonomous loop (testing phase)

```
OBSERVE (persisted observations)
   └▶ SELECT highest-priority hypothesis whose dependencies are satisfied
        └▶ EXECUTE the attack module through typed, policy-bounded tools
             └▶ ANALYZE with a deterministic criterion
                  ├ CONFIRMED   → Finding + Evidence + graph update + merge context
                  ├ DISPROVEN   → record, continue
                  └ INCONCLUSIVE→ record, continue
```

Dependencies come from the modules themselves (auth depends on disclosure; IDOR/SQLi
depend on auth), so a valid order emerges from real prerequisites, not a hardcoded script.

## Retest (proving the fix)

For each remediated finding, the retest engine builds a disposable instance with only
that fix applied, replays the module chain up to and including the target module, and
compares: `before = CONFIRMED`, `after = DISPROVEN` ⟶ **FIX VERIFIED**. Because the same
module code drives both the attack and the retest, the verdict is a genuine replay.

## The generic scanner (the product core)

Everything above proves a *specific* chain against the bundled lab. The **scanner**
(`dracarys/scanner/`) is the target-agnostic engine that makes DRACARYS a tool: it finds
real vulnerabilities in arbitrary authorized targets.

```
Scanner.scan()
  ├─ Crawler        links + forms + query params, and OpenAPI import  → RequestTemplates + baselines
  ├─ Passive        run over every captured response (headers, secrets, verbose errors)
  ├─ Active         mutate each injection point (SQLi, XSS, open redirect) via typed HTTP
  ├─ Site           exposed files/secrets, API schema, IDOR differential
  └─ Dedupe + rank  ScanFinding[]  →  reporters (table / JSON / SARIF / MD / HTML)
```

- **Oracles** (`scanner/oracles.py`) are the deterministic heart — SQL error signatures,
  boolean divergence, time-delay-with-control, unencoded-reflection, secret regexes,
  response similarity. A detector reports a finding only when an oracle fires.
- **Detectors** (`scanner/detectors/`) come in three shapes: response (passive), param
  (active), and site. Adding a detector is a small, isolated unit (see DEVELOPMENT.md).
- **Safety** is inherited from the same policy engine used by the lab modules: every
  request is scope-checked, bounded, and logged; payloads are non-destructive.
- **Reports** (`scanner/report.py`) render the same `ScanResult` to SARIF 2.1.0 (GitHub
  code scanning), JSON, Markdown, and a self-contained HTML page.
- **Runner** (`scanner/runner.py`) builds a live-network scanner for a URL behind the
  authorization gate, and is shared by the CLI (`dracarys scan`) and the API (`/api/scan`).

The scanner and the verified-remediation loop compose: for a rebuildable target you can
feed scanner findings into the campaign's remediation + retest to earn a **FIX VERIFIED**.
