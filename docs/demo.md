# DRACARYS — Guided Demo

Two ways to see the full **ATTACK → PROVE → FIX → RETEST** loop.

## 1. Headless (fastest — one command)
```bash
make setup
make demo
```
You'll see recon, five confirmed findings, two critical attack paths reaching the
treasury canary (**TARGET COMPROMISED**), generated remediations, and **FIX VERIFIED 5/5**.

Score it against ground truth:
```bash
make eval     # precision/recall/validation/retest all 1.0 → PASS
```

## 2. The command center (visual)
```bash
make setup && make web-setup
make api      # terminal 1 — API on http://127.0.0.1:8000
make web      # terminal 2 — UI on http://localhost:3000
```
Then in the browser:

1. The **DRACARYS BANK** lab target is pre-registered; its enforced scope is shown
   (loopback + lab ports only).
2. Press **🔥 UNLEASH DRACARYS**.
3. Watch the **phase tracker** advance: Scope → Recon → Plan → Attack → Validate →
   Chain → Report → Remediate → Retest → Verified.
4. When the chain lands, the banner turns to **TARGET COMPROMISED — CRITICAL ATTACK
   PATH DISCOVERED**, and the **attack graph** renders the route to the canary.
5. Expand any **finding** to read its root cause, impact, hashed **evidence**
   (request/response), and the generated **remediation** patch diff.
6. As retest completes, findings flip to **✓ FIX VERIFIED** and the banner becomes
   **FIX VERIFIED** with the security score recovering.

Use **Pause / Resume** and **Stop** (kill switch) mid-campaign to see the controls.

## What's happening under the hood
```
UNLEASH ─▶ RECON ─▶ HYPOTHESIS ─▶ CONTROLLED ATTACK ─▶ VALIDATION (evidence)
        ─▶ ATTACK CHAIN ─▶ IMPACT PROOF ─▶ REMEDIATION
        ─▶ PATCHED ENVIRONMENT ─▶ RETEST (replay) ─▶ FIX VERIFIED
```

## The attack chain you'll see
```
Verbose status leak (LAB-INFO-001)
   └▶ enables ▶ Exposed staging login (LAB-AUTH-001)
        ├▶ enables ▶ IDOR to treasury (LAB-IDOR-001) ─▶ reaches ▶ 🏆 vault canary
        └▶ enables ▶ UNION SQLi (LAB-SQL-001)         ─▶ reaches ▶ 🏆 vault canary
   (also) Privilege escalation via forged role header (LAB-MISCONFIG-001)
```
Two independent critical paths reach the same crown-jewel — then both are broken and verified.
