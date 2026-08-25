"""Pydantic API schemas (requests + responses).

Response models are flat (scalar columns only) so they serialize cleanly from
async ORM objects without triggering lazy relationship loads.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from dracarys.domain.enums import (
    CampaignState,
    Confidence,
    FindingStatus,
    HypothesisStatus,
    RetestResult,
    Severity,
    TestOutcome,
    VulnCategory,
)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# --- Requests ---------------------------------------------------------------

class TargetCreate(BaseModel):
    name: str
    base_url: str
    description: str = ""
    allowed_hosts: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    is_lab: bool = True


class CampaignCreate(BaseModel):
    target_id: str
    name: str = "Untitled campaign"
    objective: str = "Discover and prove an attack chain, then verify fixes."
    canary_token: str | None = None


class ValidateTargetRequest(BaseModel):
    base_url: str
    allowed_hosts: list[str] | None = None
    allowed_ports: list[int] | None = None


# --- Responses --------------------------------------------------------------

class TargetOut(ORMModel):
    id: str
    name: str
    base_url: str
    description: str
    allowed_hosts: list[str]
    allowed_ports: list[int]
    is_lab: bool
    validated: bool
    created_at: datetime


class ScopeDecisionOut(BaseModel):
    allowed: bool
    reason: str
    host: str | None = None
    port: int | None = None
    resolved_ips: list[str] = Field(default_factory=list)


class CampaignOut(ORMModel):
    id: str
    target_id: str
    name: str
    objective: str
    state: CampaignState
    scope: dict
    policy: dict
    progress: dict
    requests_made: int
    security_score: int
    error: str | None = None
    control: str = ""
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ObservationOut(ORMModel):
    id: str
    source: str
    kind: str
    description: str
    data: dict
    confidence: float
    evidence_refs: list[str]
    created_at: datetime


class HypothesisOut(ORMModel):
    id: str
    category: VulnCategory
    module_id: str
    title: str
    rationale: str
    target_asset: str
    expected_outcome: str
    priority: float
    status: HypothesisStatus
    planner: str
    observation_refs: list[str]
    created_at: datetime


class FindingOut(ORMModel):
    id: str
    hypothesis_id: str | None = None
    ground_truth_id: str | None = None
    category: VulnCategory
    title: str
    severity: Severity
    confidence: Confidence
    affected_asset: str
    root_cause: str
    impact: str
    description: str
    evidence_refs: list[str]
    status: FindingStatus
    created_at: datetime


class EvidenceOut(ORMModel):
    id: str
    kind: str
    tool: str
    summary: str
    request_meta: dict
    response_meta: dict
    content: dict
    sha256: str
    observation_id: str | None = None
    test_run_id: str | None = None
    finding_id: str | None = None
    reproducible: bool
    created_at: datetime


class TestRunOut(ORMModel):
    id: str
    hypothesis_id: str | None = None
    tool: str
    parameters: dict
    outcome: TestOutcome
    detail: str
    result: dict
    duration_ms: int
    evidence_refs: list[str]
    created_at: datetime


class AttackPathOut(ORMModel):
    id: str
    title: str
    nodes: list[dict]
    edges: list[dict]
    finding_ids: list[str]
    impact: str
    severity: Severity
    confidence: Confidence
    reaches_canary: bool
    created_at: datetime


class RemediationOut(ORMModel):
    id: str
    finding_id: str
    ground_truth_id: str | None = None
    summary: str
    root_cause: str
    recommendation: str
    patch_diff: str
    patch_ref: str
    verification_test: str
    generated_by: str
    created_at: datetime


class RetestOut(ORMModel):
    id: str
    finding_id: str
    remediation_id: str | None = None
    result: RetestResult
    patched_base_url: str
    before_outcome: TestOutcome
    after_outcome: TestOutcome
    detail: str
    before_evidence_id: str | None = None
    after_evidence_id: str | None = None
    created_at: datetime


class AuditEventOut(ORMModel):
    id: str
    campaign_id: str | None = None
    actor: str
    action: str
    target: str
    result: str
    detail: dict
    created_at: datetime


class GraphNodeOut(BaseModel):
    ref: str
    type: str
    label: str
    data: dict = Field(default_factory=dict)


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    type: str
    data: dict = Field(default_factory=dict)


class GraphOut(BaseModel):
    nodes: list[GraphNodeOut]
    edges: list[GraphEdgeOut]


class CampaignSummary(BaseModel):
    campaign: CampaignOut
    counts: dict[str, int]
    severity_breakdown: dict[str, int]
    target_compromised: bool
    fixes_verified: int
    fixes_attempted: int


class ErrorOut(BaseModel):
    error: str
    detail: Any | None = None


class ScanRequest(BaseModel):
    url: str
    active: bool = True
    include_time_based: bool = False
    max_pages: int = 40
    max_requests: int = 1500
    auth_headers: dict[str, str] = Field(default_factory=dict)
    # Required to scan a non-loopback target (mirrors the CLI safety gate).
    authorized: bool = False
