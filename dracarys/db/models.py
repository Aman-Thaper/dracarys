"""SQLAlchemy ORM models — the persistent domain of DRACARYS.

The database is the single source of truth for campaign state; nothing critical
lives only in conversational/agent memory.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    JSON,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from dracarys.db.base import (
    Base,
    EnumType,
    TZDateTime,
    created_column,
    pk_column,
    updated_column,
)
from dracarys.domain.enums import (
    AssetType,
    CampaignState,
    Confidence,
    FindingStatus,
    GraphEdgeType,
    GraphNodeType,
    HypothesisStatus,
    RetestResult,
    Severity,
    TestOutcome,
    VulnCategory,
)


class Target(Base):
    """An authorized target of a campaign (the DRACARYS LAB by default)."""

    __tablename__ = "targets"

    id: Mapped[str] = pk_column("tgt")
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    base_url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    # The scope this target is allowed to be tested under.
    allowed_hosts: Mapped[list] = mapped_column(JSON, default=list)
    allowed_ports: Mapped[list] = mapped_column(JSON, default=list)
    is_lab: Mapped[bool] = mapped_column(default=True)
    validated: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    campaigns: Mapped[list[Campaign]] = relationship(back_populates="target")


class Campaign(Base):
    __tablename__ = "campaigns"

    id: Mapped[str] = pk_column("cmp")
    target_id: Mapped[str] = mapped_column(ForeignKey("targets.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), default="")
    objective: Mapped[str] = mapped_column(Text, default="")
    state: Mapped[CampaignState] = mapped_column(
        EnumType(CampaignState), default=CampaignState.CREATED
    )
    # Effective scope snapshot (immutable during the campaign).
    scope: Mapped[dict] = mapped_column(JSON, default=dict)
    policy: Mapped[dict] = mapped_column(JSON, default=dict)
    budget: Mapped[dict] = mapped_column(JSON, default=dict)
    # Live progress + resource accounting.
    progress: Mapped[dict] = mapped_column(JSON, default=dict)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    security_score: Mapped[int] = mapped_column(Integer, default=100)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    kill_switch: Mapped[bool] = mapped_column(default=False)
    # Operator control channel: "" | "pause" | "stop".
    control: Mapped[str] = mapped_column(String(20), default="")
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()
    started_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)

    target: Mapped[Target] = relationship(back_populates="campaigns")
    assets: Mapped[list[Asset]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    observations: Mapped[list[Observation]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    hypotheses: Mapped[list[Hypothesis]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )
    findings: Mapped[list[Finding]] = relationship(
        back_populates="campaign", cascade="all, delete-orphan"
    )


class Asset(Base):
    """A discovered element of the attack surface (endpoint, identity, etc.)."""

    __tablename__ = "assets"

    id: Mapped[str] = pk_column("ast")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    type: Mapped[AssetType] = mapped_column(EnumType(AssetType), nullable=False)
    address: Mapped[str] = mapped_column(String(500), nullable=False)
    asset_metadata: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()

    campaign: Mapped[Campaign] = relationship(back_populates="assets")


class Observation(Base):
    """A concrete fact recon/testing learned about the target."""

    __tablename__ = "observations"

    id: Mapped[str] = pk_column("obs")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    source: Mapped[str] = mapped_column(String(60), default="recon")
    kind: Mapped[str] = mapped_column(String(60), default="generic")
    description: Mapped[str] = mapped_column(Text, default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = created_column()

    campaign: Mapped[Campaign] = relationship(back_populates="observations")


class Hypothesis(Base):
    """A falsifiable belief about a possible weakness, produced by the planner."""

    __tablename__ = "hypotheses"

    id: Mapped[str] = pk_column("hyp")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    category: Mapped[VulnCategory] = mapped_column(EnumType(VulnCategory), nullable=False)
    # Attack module that tests this hypothesis (equals the ground-truth candidate id).
    module_id: Mapped[str] = mapped_column(String(40), default="")
    title: Mapped[str] = mapped_column(String(300), default="")
    rationale: Mapped[str] = mapped_column(Text, default="")
    observation_refs: Mapped[list] = mapped_column(JSON, default=list)
    target_asset: Mapped[str] = mapped_column(String(500), default="")
    expected_outcome: Mapped[str] = mapped_column(Text, default="")
    success_criteria: Mapped[dict] = mapped_column(JSON, default=dict)
    priority: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[HypothesisStatus] = mapped_column(
        EnumType(HypothesisStatus), default=HypothesisStatus.PROPOSED
    )
    # Which planner produced this and why (audit of agent reasoning).
    planner: Mapped[str] = mapped_column(String(40), default="heuristic")
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    campaign: Mapped[Campaign] = relationship(back_populates="hypotheses")
    test_runs: Mapped[list[TestRun]] = relationship(
        back_populates="hypothesis", cascade="all, delete-orphan"
    )


class TestRun(Base):
    """A single bounded execution of a typed tool against the target."""

    __test__ = False  # not a pytest test class
    __tablename__ = "test_runs"

    id: Mapped[str] = pk_column("run")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    hypothesis_id: Mapped[str | None] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=True
    )
    tool: Mapped[str] = mapped_column(String(40), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, default=dict)
    outcome: Mapped[TestOutcome] = mapped_column(EnumType(TestOutcome), nullable=False)
    detail: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = created_column()

    hypothesis: Mapped[Hypothesis] = relationship(back_populates="test_runs")


class Finding(Base):
    """A validated vulnerability, backed by deterministic evidence."""

    __tablename__ = "findings"

    id: Mapped[str] = pk_column("fnd")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    hypothesis_id: Mapped[str | None] = mapped_column(
        ForeignKey("hypotheses.id"), nullable=True
    )
    # Ground-truth id in the lab (e.g. LAB-SQL-001), when known/matched.
    ground_truth_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    category: Mapped[VulnCategory] = mapped_column(EnumType(VulnCategory), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    severity: Mapped[Severity] = mapped_column(EnumType(Severity), nullable=False)
    confidence: Mapped[Confidence] = mapped_column(
        EnumType(Confidence), default=Confidence.CONFIRMED
    )
    affected_asset: Mapped[str] = mapped_column(String(500), default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    impact: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    evidence_refs: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[FindingStatus] = mapped_column(
        EnumType(FindingStatus), default=FindingStatus.OPEN
    )
    created_at: Mapped[datetime] = created_column()
    updated_at: Mapped[datetime] = updated_column()

    campaign: Mapped[Campaign] = relationship(back_populates="findings")
    remediation: Mapped[Remediation | None] = relationship(
        back_populates="finding",
        cascade="all, delete-orphan",
        uselist=False,
    )


class Evidence(Base):
    """First-class, immutable proof. Findings cite evidence, not model prose."""

    __tablename__ = "evidence"

    id: Mapped[str] = pk_column("evd")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(60), default="http_exchange")
    tool: Mapped[str] = mapped_column(String(40), default="")
    summary: Mapped[str] = mapped_column(Text, default="")
    request_meta: Mapped[dict] = mapped_column(JSON, default=dict)
    response_meta: Mapped[dict] = mapped_column(JSON, default=dict)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    # Integrity fingerprint over the captured content.
    sha256: Mapped[str] = mapped_column(String(64), default="")
    # Backlinks for provenance.
    observation_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    test_run_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    finding_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    reproducible: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = created_column()


class AttackPath(Base):
    """A multi-step chain relating findings into a route to a protected resource."""

    __tablename__ = "attack_paths"

    id: Mapped[str] = pk_column("path")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    title: Mapped[str] = mapped_column(String(300), default="")
    nodes: Mapped[list] = mapped_column(JSON, default=list)
    edges: Mapped[list] = mapped_column(JSON, default=list)
    finding_ids: Mapped[list] = mapped_column(JSON, default=list)
    impact: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[Severity] = mapped_column(EnumType(Severity), default=Severity.HIGH)
    confidence: Mapped[Confidence] = mapped_column(
        EnumType(Confidence), default=Confidence.CONFIRMED
    )
    reaches_canary: Mapped[bool] = mapped_column(default=False)
    created_at: Mapped[datetime] = created_column()


class GraphNode(Base):
    """Persisted attack-graph node (assets, identities, vulns, resources...)."""

    __tablename__ = "graph_nodes"

    id: Mapped[str] = pk_column("gn")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    type: Mapped[GraphNodeType] = mapped_column(EnumType(GraphNodeType), nullable=False)
    label: Mapped[str] = mapped_column(String(300), default="")
    # Stable natural key so recon/testing can upsert the same node repeatedly.
    ref: Mapped[str] = mapped_column(String(300), default="")
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()


class GraphEdge(Base):
    __tablename__ = "graph_edges"

    id: Mapped[str] = pk_column("ge")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    source_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    target_ref: Mapped[str] = mapped_column(String(300), nullable=False)
    type: Mapped[GraphEdgeType] = mapped_column(EnumType(GraphEdgeType), nullable=False)
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()


class Remediation(Base):
    __tablename__ = "remediations"

    id: Mapped[str] = pk_column("rem")
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"), nullable=False, unique=True
    )
    ground_truth_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    root_cause: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[str] = mapped_column(Text, default="")
    patch_diff: Mapped[str] = mapped_column(Text, default="")
    patch_ref: Mapped[str] = mapped_column(String(200), default="")
    verification_test: Mapped[str] = mapped_column(Text, default="")
    generated_by: Mapped[str] = mapped_column(String(40), default="remediation-agent")
    created_at: Mapped[datetime] = created_column()

    finding: Mapped[Finding] = relationship(back_populates="remediation")
    retests: Mapped[list[Retest]] = relationship(
        back_populates="remediation", cascade="all, delete-orphan"
    )


class Retest(Base):
    """A replay of the original attack against the patched environment."""

    __tablename__ = "retests"

    id: Mapped[str] = pk_column("rt")
    campaign_id: Mapped[str] = mapped_column(
        ForeignKey("campaigns.id"), nullable=False
    )
    finding_id: Mapped[str] = mapped_column(
        ForeignKey("findings.id"), nullable=False
    )
    remediation_id: Mapped[str | None] = mapped_column(
        ForeignKey("remediations.id"), nullable=True
    )
    result: Mapped[RetestResult] = mapped_column(
        EnumType(RetestResult), default=RetestResult.NOT_RUN
    )
    patched_base_url: Mapped[str] = mapped_column(String(500), default="")
    before_outcome: Mapped[TestOutcome] = mapped_column(
        EnumType(TestOutcome), default=TestOutcome.CONFIRMED
    )
    after_outcome: Mapped[TestOutcome] = mapped_column(
        EnumType(TestOutcome), default=TestOutcome.INCONCLUSIVE
    )
    detail: Mapped[str] = mapped_column(Text, default="")
    before_evidence_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    after_evidence_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    created_at: Mapped[datetime] = created_column()

    remediation: Mapped[Remediation | None] = relationship(back_populates="retests")


class AuditEvent(Base):
    """Append-only audit trail: every offensive action is authorized and logged."""

    __tablename__ = "audit_events"

    id: Mapped[str] = pk_column("aud")
    campaign_id: Mapped[str | None] = mapped_column(String(48), nullable=True)
    actor: Mapped[str] = mapped_column(String(80), default="orchestrator")
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target: Mapped[str] = mapped_column(String(500), default="")
    result: Mapped[str] = mapped_column(String(40), default="ok")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = created_column()
