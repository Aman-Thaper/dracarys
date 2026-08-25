"""Enumerations that form the shared vocabulary of the DRACARYS domain."""
from __future__ import annotations

from enum import Enum


class CampaignState(str, Enum):
    """Persisted campaign lifecycle (see engine/orchestrator/state_machine.py)."""

    CREATED = "CREATED"
    SCOPING = "SCOPING"
    RECON = "RECON"
    ATTACK_PLANNING = "ATTACK_PLANNING"
    TESTING = "TESTING"
    VALIDATION = "VALIDATION"
    ATTACK_CHAIN_ANALYSIS = "ATTACK_CHAIN_ANALYSIS"
    REPORTING = "REPORTING"
    REMEDIATION = "REMEDIATION"
    RETEST = "RETEST"
    COMPLETE = "COMPLETE"
    # Terminal / control states
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PAUSED = "PAUSED"


# States from which a campaign may still do offensive work (used by kill switch).
ACTIVE_STATES = {
    CampaignState.SCOPING,
    CampaignState.RECON,
    CampaignState.ATTACK_PLANNING,
    CampaignState.TESTING,
    CampaignState.VALIDATION,
    CampaignState.ATTACK_CHAIN_ANALYSIS,
    CampaignState.REMEDIATION,
    CampaignState.RETEST,
}

TERMINAL_STATES = {
    CampaignState.COMPLETE,
    CampaignState.FAILED,
    CampaignState.CANCELLED,
}


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]


class Confidence(str, Enum):
    CONFIRMED = "confirmed"   # deterministic proof captured
    FIRM = "firm"             # strong evidence, minor ambiguity
    TENTATIVE = "tentative"   # suggestive only


class VulnCategory(str, Enum):
    SQL_INJECTION = "sql_injection"
    IDOR = "idor"                       # broken object-level authorization
    BROKEN_AUTH = "broken_auth"
    INFO_DISCLOSURE = "info_disclosure"
    SECURITY_MISCONFIG = "security_misconfig"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    XSS = "xss"
    OPEN_REDIRECT = "open_redirect"
    SENSITIVE_DATA = "sensitive_data"
    EXPOSED_RESOURCE = "exposed_resource"
    VERBOSE_ERROR = "verbose_error"


class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"


class FindingStatus(str, Enum):
    OPEN = "open"
    REMEDIATION_PROPOSED = "remediation_proposed"
    RETEST_PENDING = "retest_pending"
    FIX_VERIFIED = "fix_verified"
    FIX_FAILED = "fix_failed"


class TestOutcome(str, Enum):
    __test__ = False  # not a pytest test class

    CONFIRMED = "confirmed"
    DISPROVEN = "disproven"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"
    BLOCKED_BY_POLICY = "blocked_by_policy"


class ToolName(str, Enum):
    HTTP = "http"
    RECON = "recon"
    STATIC = "static"


class AssetType(str, Enum):
    HOST = "host"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    IDENTITY = "identity"
    RESOURCE = "resource"


class GraphNodeType(str, Enum):
    ASSET = "asset"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    VULNERABILITY = "vulnerability"
    PRIVILEGE = "privilege"
    RESOURCE = "resource"
    EVIDENCE = "evidence"
    REMEDIATION = "remediation"


class GraphEdgeType(str, Enum):
    DISCOVERS = "discovers"
    EXPOSES = "exposes"
    AUTHENTICATES_AS = "authenticates_as"
    BYPASSES = "bypasses"
    ENABLES = "enables"
    REACHES = "reaches"
    DEPENDS_ON = "depends_on"
    FIXES = "fixes"
    INVALIDATES = "invalidates"


class RetestResult(str, Enum):
    FIX_VERIFIED = "fix_verified"
    FIX_FAILED = "fix_failed"
    NOT_RUN = "not_run"
