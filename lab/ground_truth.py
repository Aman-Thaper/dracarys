"""Ground truth for the DRACARYS LAB.

This is the objective answer key the evaluation harness scores DRACARYS against.
Each entry documents where the flaw lives, how to prove it deterministically,
and what a correct fix looks like.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from dracarys.domain.enums import Severity, VulnCategory

# The single crown-jewel canary. Reaching it in a response body is objective
# proof that a protected resource was compromised. Obviously synthetic.
CANARY_TOKEN = "DRACARYS_CANARY{v4ult-r3c0v3ry-7Q2X-9F1B}"

# Credential intentionally leaked by LAB-INFO-001 and reused by LAB-AUTH-001.
LEAKED_USER = "qa_bot"
LEAKED_PASSWORD = "qa-staging-7f3a91"

# The protected treasury account holding the canary (reached via IDOR).
TREASURY_ACCOUNT_ID = 9001


@dataclass(frozen=True)
class GroundTruthVuln:
    id: str
    category: VulnCategory
    severity: Severity
    title: str
    location: str              # method + path
    description: str
    vulnerable_behavior: str
    patched_behavior: str
    validation_criteria: str   # deterministic pass condition
    expected_evidence: str
    expected_impact: str
    enables: list[str] = field(default_factory=list)  # ground-truth chain edges


GROUND_TRUTH: dict[str, GroundTruthVuln] = {
    "LAB-INFO-001": GroundTruthVuln(
        id="LAB-INFO-001",
        category=VulnCategory.INFO_DISCLOSURE,
        severity=Severity.HIGH,
        title="Verbose status endpoint discloses staging credentials",
        location="GET /api/system/status?verbose=1",
        description=(
            "An unauthenticated diagnostic endpoint returns internal build notes "
            "when called with verbose=1, disclosing a seeded staging service "
            "account's credentials and the internal account-numbering scheme."
        ),
        vulnerable_behavior=(
            "verbose=1 dumps a 'debug' block containing qa_bot's plaintext "
            "password and the treasury account id."
        ),
        patched_behavior="verbose flag is ignored; no debug block is returned.",
        validation_criteria=(
            "Response 200 and body contains a credential for the leaked user."
        ),
        expected_evidence="HTTP exchange showing the leaked credential in the body.",
        expected_impact="Attacker obtains valid credentials without authenticating.",
        enables=["LAB-AUTH-001"],
    ),
    "LAB-AUTH-001": GroundTruthVuln(
        id="LAB-AUTH-001",
        category=VulnCategory.BROKEN_AUTH,
        severity=Severity.HIGH,
        title="Exposed staging account is live in production",
        location="POST /api/login",
        description=(
            "The staging service account disclosed by LAB-INFO-001 is a valid, "
            "enabled login, granting an authenticated session to anyone holding "
            "the leaked artifact."
        ),
        vulnerable_behavior="Login with leaked qa_bot credentials succeeds.",
        patched_behavior="The qa_bot service account is disabled (401).",
        validation_criteria=(
            "Login returns a token that authenticates as the leaked user on /api/me."
        ),
        expected_evidence="Login exchange yielding a working bearer token.",
        expected_impact="Attacker gains an authenticated foothold as a service user.",
        enables=["LAB-IDOR-001", "LAB-SQL-001", "LAB-MISCONFIG-001"],
    ),
    "LAB-IDOR-001": GroundTruthVuln(
        id="LAB-IDOR-001",
        category=VulnCategory.IDOR,
        severity=Severity.CRITICAL,
        title="Broken object-level authorization on account access",
        location="GET /api/accounts/{id}",
        description=(
            "Any authenticated user can read any account by id; there is no check "
            "that the account belongs to the caller. The treasury account holds a "
            "vault recovery canary."
        ),
        vulnerable_behavior=(
            "A low-privilege session reads the treasury account and its canary."
        ),
        patched_behavior="Non-owner, non-admin access returns 403.",
        validation_criteria=(
            "Low-priv session GETs the treasury account and the body contains the "
            "canary token."
        ),
        expected_evidence="Authenticated exchange returning the canary token.",
        expected_impact="Full compromise of the protected treasury resource.",
        enables=[],
    ),
    "LAB-SQL-001": GroundTruthVuln(
        id="LAB-SQL-001",
        category=VulnCategory.SQL_INJECTION,
        severity=Severity.CRITICAL,
        title="UNION-based SQL injection in account search",
        location="GET /api/accounts/search?q=",
        description=(
            "The search query is built by string concatenation, allowing a "
            "UNION-based injection to exfiltrate the secrets table (which stores "
            "the vault recovery canary)."
        ),
        vulnerable_behavior=(
            "A crafted q parameter unions rows from the secrets table into results."
        ),
        patched_behavior="Query is parameterized; injection is inert.",
        validation_criteria=(
            "Injected query returns the canary token while a benign control query "
            "does not."
        ),
        expected_evidence="Paired control/injection exchanges proving exfiltration.",
        expected_impact="Database exfiltration reaching the protected canary.",
        enables=[],
    ),
    "LAB-MISCONFIG-001": GroundTruthVuln(
        id="LAB-MISCONFIG-001",
        category=VulnCategory.PRIVILEGE_ESCALATION,
        severity=Severity.HIGH,
        title="Admin endpoint trusts a client-supplied role header",
        location="GET /api/admin/users",
        description=(
            "Authorization for the admin user dump is granted when a client sends "
            "X-Account-Role: admin, instead of relying on the session's real role."
        ),
        vulnerable_behavior=(
            "A non-admin session with X-Account-Role: admin dumps all users."
        ),
        patched_behavior="Authorization uses the session role only; header ignored.",
        validation_criteria=(
            "Request without the header is 403; the same request with the header "
            "is 200 and dumps user records."
        ),
        expected_evidence="Paired exchanges showing header-controlled authorization.",
        expected_impact="Privilege escalation to admin-only data (password hashes).",
        enables=[],
    ),
}

ALL_PATCH_IDS = list(GROUND_TRUTH.keys())


def patch_all() -> set[str]:
    return set(ALL_PATCH_IDS)
