"""Remediation agent — root-cause analysis, fix, patch, and a verification test.

For each confirmed finding it emits a Remediation: the concrete code change (a
real unified diff against the lab), a patch reference the retest engine applies to
spin up a patched environment, and the deterministic test that must now fail.

The mapping is deterministic and keyed to ground truth because the correct fix for
each weakness is known; an LLM provider could author the same fields (see
llm_planner for the provider-agnostic pattern), but a fix that is verified by
replay does not need to be model-authored to be trustworthy.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RemediationPlan:
    ground_truth_id: str
    summary: str
    recommendation: str
    patch_diff: str
    patch_ref: str          # applied by the retest engine to build a patched lab
    verification_test: str


_REMEDIATIONS: dict[str, RemediationPlan] = {
    "LAB-INFO-001": RemediationPlan(
        ground_truth_id="LAB-INFO-001",
        summary="Stop returning debug material from the diagnostic endpoint.",
        recommendation=(
            "Remove the verbose debug branch or gate it behind an authenticated, "
            "authorized admin role. Never embed seed credentials in responses."
        ),
        patch_diff=(
            "--- a/lab/app.py\n+++ b/lab/app.py\n"
            "@@ def system_status\n"
            "-    if verbose and not state.patched(\"LAB-INFO-001\"):\n"
            "-        # VULNERABLE: leaks seeded staging credentials\n"
            "-        body[\"debug\"] = {\"seed_accounts\": [...secrets...]}\n"
            "+    if verbose:\n"
            "+        body[\"debug\"] = {\"note\": \"verbose diagnostics disabled\"}\n"
        ),
        patch_ref="LAB-INFO-001",
        verification_test=(
            "GET /api/system/status?verbose=1 must not contain any credential."
        ),
    ),
    "LAB-AUTH-001": RemediationPlan(
        ground_truth_id="LAB-AUTH-001",
        summary="Disable the exposed staging service account in production.",
        recommendation=(
            "Remove or disable seeded non-production accounts before deploy, and "
            "rotate any leaked credential. Enforce credential hygiene in CI."
        ),
        patch_diff=(
            "--- a/lab/app.py\n+++ b/lab/app.py\n"
            "@@ def login\n"
            "+    if username == \"qa_bot\":\n"
            "+        # staging service account is disabled in production\n"
            "+        return JSONResponse({\"error\": \"account disabled\"}, status_code=401)\n"
        ),
        patch_ref="LAB-AUTH-001",
        verification_test=(
            "POST /api/login with the leaked qa_bot credentials must return 401."
        ),
    ),
    "LAB-IDOR-001": RemediationPlan(
        ground_truth_id="LAB-IDOR-001",
        summary="Enforce object-level authorization on account reads.",
        recommendation=(
            "Verify the authenticated caller owns the requested account (or is an "
            "admin) before returning it. Apply the check to every object endpoint."
        ),
        patch_diff=(
            "--- a/lab/app.py\n+++ b/lab/app.py\n"
            "@@ def get_account\n"
            "+    if row[\"owner_username\"] != user[\"username\"] and user[\"role\"] != \"admin\":\n"
            "+        return JSONResponse({\"error\": \"forbidden\"}, status_code=403)\n"
        ),
        patch_ref="LAB-IDOR-001",
        verification_test=(
            "A non-owner session GET /api/accounts/9001 must return 403 without the "
            "canary."
        ),
    ),
    "LAB-SQL-001": RemediationPlan(
        ground_truth_id="LAB-SQL-001",
        summary="Parameterize the account search query.",
        recommendation=(
            "Use bound parameters instead of string concatenation for all SQL. "
            "Add a lint/CI rule to forbid f-string SQL."
        ),
        patch_diff=(
            "--- a/lab/app.py\n+++ b/lab/app.py\n"
            "@@ def account_search\n"
            "-    sql = f\"SELECT id, holder_name, kind FROM accounts \"\n"
            "-          f\"WHERE holder_name LIKE '%{q}%'\"\n"
            "-    rows = state.db.execute(sql).fetchall()\n"
            "+    sql = \"SELECT id, holder_name, kind FROM accounts WHERE holder_name LIKE ?\"\n"
            "+    rows = state.db.execute(sql, (f\"%{q}%\",)).fetchall()\n"
        ),
        patch_ref="LAB-SQL-001",
        verification_test=(
            "The UNION injection query must not return the canary; the control "
            "query behaves normally."
        ),
    ),
    "LAB-MISCONFIG-001": RemediationPlan(
        ground_truth_id="LAB-MISCONFIG-001",
        summary="Authorize on the session role, never a client-supplied header.",
        recommendation=(
            "Derive authorization solely from the authenticated session. Never "
            "trust client-provided role/identity headers for access decisions."
        ),
        patch_diff=(
            "--- a/lab/app.py\n+++ b/lab/app.py\n"
            "@@ def admin_users\n"
            "-    is_admin = (user[\"role\"] == \"admin\"\n"
            "-                or request.headers.get(\"X-Account-Role\") == \"admin\")\n"
            "+    is_admin = user[\"role\"] == \"admin\"\n"
        ),
        patch_ref="LAB-MISCONFIG-001",
        verification_test=(
            "GET /api/admin/users with a forged X-Account-Role: admin header must "
            "still return 403 for a non-admin session."
        ),
    ),
}


class RemediationAgent:
    name = "remediation-agent"

    def plan_for(self, ground_truth_id: str | None) -> RemediationPlan | None:
        if not ground_truth_id:
            return None
        return _REMEDIATIONS.get(ground_truth_id)
