# DRACARYS — Security & Safety Model

DRACARYS performs offensive actions. It is engineered so those actions are
**authorized, scoped, bounded, observable, and reversible** — and so it is difficult
to accidentally point them at anything other than the local lab.

## Threat model for the tool itself

The primary risk in an autonomous offensive agent is that the language model, given
freedom, targets the wrong system or performs an unbounded/destructive action.
DRACARYS removes that freedom by construction:

- **The model never executes commands.** It emits *typed tool requests*
  (`HttpRequestSpec`) that are validated by Pydantic before anything runs. There is no
  shell tool, no `eval`, no arbitrary process execution.
- **Every request passes the policy/scope engine** before it touches the network.

## The authorization & isolation model

```
Planner ─▶ Typed tool request ─▶ PolicyEngine.guard(url) ─▶ bounded HTTP ─▶ Evidence
                                        │
             ┌──────────────────────────┴───────────────────────────┐
             │ scheme http(s) only · no embedded credentials ·        │
             │ host ∈ allowlist · port ∈ allowlist ·                  │
             │ host resolves to private/loopback · budget not spent · │
             │ concurrency slot free · kill switch not engaged        │
             └────────────────────────────────────────────────────────┘
```

### Controls

| Control | Where | Default |
|---|---|---|
| Target allowlist (host) | `Scope` | `127.0.0.1`, `localhost`, `::1` |
| Port allowlist | `Scope` | `8888`, `8889` |
| Private/loopback resolution check | `scope.validate_url` | required |
| Scheme restriction | `scope.validate_url` | `http`, `https` only |
| Reject embedded credentials in URL | `scope.validate_url` | on |
| Per-campaign request budget | `PolicyEngine` | 2000 |
| Concurrency limit | `PolicyEngine` | 8 |
| Per-call timeout | `PolicyEngine` | 10s |
| Campaign kill switch (STOP) | `PolicyEngine` / orchestrator | operator-triggered |
| Complete audit log | `AuditEvent` | every offensive action |

The private/loopback resolution check is defense-in-depth: even if a hostname is added
to the allowlist, DRACARYS refuses it unless it resolves to a private/loopback address.
This blocks typos and DNS-rebinding-style mistakes that would otherwise reach the internet.

### Fail-closed scoping

If a campaign's target is out of scope, the scope gate transitions the campaign to
`FAILED` **before any recon or attack runs**, and records a denied `scope_validated`
audit event. No findings, no requests. (Covered by an e2e test.)

## Evidence integrity

Findings cite evidence, not model prose. Each evidence record stores request/response
metadata, a body preview, and a **SHA-256** fingerprint of the captured body. Sensitive
request headers (`Authorization`, `Cookie`, `X-API-Key`) are **redacted** before an
exchange is persisted, so session tokens never land in the evidence store.

## Data safety

- **All lab data is synthetic.** Users, balances, and "credentials" are fabricated.
- The crown-jewel is an obvious canary token (`DRACARYS_CANARY{…}`), used purely as a
  deterministic proof-of-reach signal — reaching it is how the engine proves impact.
- No real secrets, credentials, or PII are used anywhere. `.env.example` ships only
  local-only, non-sensitive defaults; `.env` is git-ignored.

## Honesty guarantees

DRACARYS is built to avoid the failure modes that make "AI security" demos misleading:

- No hardcoded exploitation results — attacks make real requests and are validated by
  code, and the same modules run in tests against both vulnerable and patched apps.
- No simulated vulnerabilities — the lab's flaws are genuinely exploitable code paths.
- No fake "fix verified" — the verdict requires the original attack to be replayed
  against a patched instance and to actually fail (`confirmed → disproven`).

## Responsible use

DRACARYS targets the bundled, deliberately vulnerable lab. Pointing it at any system you
are not explicitly authorized to test is out of scope for this project and, in general,
may be unlawful. The default configuration is loopback-only by design; widening scope is
a deliberate, auditable act.

## Scanning real (non-lab) targets

The generic scanner can be pointed at arbitrary authorized targets, so it carries an
explicit consent-and-containment model:

- **Authorization gate** (`scanner/runner.authorize`): loopback targets are allowed for
  convenience (your own machine); **any other host is refused** unless the operator passes
  `--yes-i-am-authorized` (CLI), `authorized: true` (API), or sets `DRACARYS_AUTHORIZED=1`.
- **Scope is derived from the target** and enforced by the policy engine: the scanner may
  only reach the target host/port (plus any explicit `--scope` additions). It cannot wander
  to third-party hosts even via discovered links.
- **Non-destructive payloads only:** read-only SQL (no `DROP`/`DELETE`/`UPDATE`), benign
  unique XSS markers (never stored), short bounded sleeps for time-based tests, and OOB
  hosts that are never actually contacted (only the target's `Location` header is inspected).
  Active testing is opt-out via `--passive`.
- **Budgets:** each scan has a hard request budget, concurrency cap, and per-request
  timeout; it degrades gracefully (and stops) when the budget is exhausted.
- **Evidence redaction:** `Authorization`, `Cookie`, and `X-API-Key` values are redacted
  before evidence is persisted or exported.

**Responsible use.** DRACARYS is for authorized security testing only. Scanning systems you
do not own or have explicit permission to test may be unlawful; the loopback-only default
and the authorization gate exist to keep the easy path the safe one.
