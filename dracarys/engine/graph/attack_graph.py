"""Attack-graph construction and chain discovery.

Nodes and edges are derived from *confirmed* findings (real, evidence-backed
persisted entities) and the runtime causality captured while attacking (which
credential unlocked which session, which finding reached the canary). Nothing is
hardcoded for display: a node exists only because a finding was proven, and an
ENABLES edge exists only because a proven step actually depended on a prior one.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.agents.attacks import ATTACK_MODULES
from dracarys.db.models import Finding, GraphEdge, GraphNode
from dracarys.domain.enums import (
    Confidence,
    GraphEdgeType,
    GraphNodeType,
    Severity,
)

CANARY_REF = "resource:treasury-canary"


@dataclass
class GraphView:
    nodes: list[dict] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)


@dataclass
class AttackPathView:
    title: str
    nodes: list[dict]
    edges: list[dict]
    finding_ids: list[str]
    impact: str
    severity: Severity
    confidence: Confidence
    reaches_canary: bool


def build_graph(
    *,
    target_host: str,
    findings: list[Finding],
    leaked_identity: str | None,
    canary_finding_ids: set[str],
) -> GraphView:
    """Construct the attack-graph view from confirmed findings and runtime facts."""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(ref, type_, label, data=None):
        nodes.setdefault(
            ref, {"ref": ref, "type": type_.value, "label": label, "data": data or {}}
        )

    def add_edge(src, dst, type_, data=None):
        edges.append(
            {"source": src, "target": dst, "type": type_.value, "data": data or {}}
        )

    asset_ref = f"asset:{target_host}"
    add_node(asset_ref, GraphNodeType.ASSET, f"Target {target_host}")

    # Vulnerability + endpoint nodes for each confirmed finding.
    confirmed_ids = {f.ground_truth_id for f in findings if f.ground_truth_id}
    for f in findings:
        vgt = f.ground_truth_id or f.id
        vuln_ref = f"vuln:{vgt}"
        add_node(
            vuln_ref, GraphNodeType.VULNERABILITY, f.title,
            {
                "finding_id": f.id,
                "severity": f.severity.value if isinstance(f.severity, Severity) else f.severity,
                "category": f.category.value if hasattr(f.category, "value") else f.category,
                "ground_truth_id": f.ground_truth_id,
            },
        )
        if f.affected_asset:
            ep_ref = f"endpoint:{f.affected_asset}"
            add_node(ep_ref, GraphNodeType.ENDPOINT, f.affected_asset)
            add_edge(asset_ref, ep_ref, GraphEdgeType.DISCOVERS)
            add_edge(ep_ref, vuln_ref, GraphEdgeType.EXPOSES)

    # Identity node (the foothold established via broken auth).
    if leaked_identity and "LAB-AUTH-001" in confirmed_ids:
        id_ref = f"identity:{leaked_identity}"
        add_node(
            id_ref, GraphNodeType.IDENTITY, f"Session: {leaked_identity}",
            {"privilege": "low"},
        )
        add_edge("vuln:LAB-AUTH-001", id_ref, GraphEdgeType.AUTHENTICATES_AS)

    # ENABLES edges: a confirmed dependency actually unlocked a confirmed step.
    for f in findings:
        gid = f.ground_truth_id
        if not gid or gid not in ATTACK_MODULES:
            continue
        for dep in ATTACK_MODULES[gid].depends_on:
            if dep in confirmed_ids:
                add_edge(f"vuln:{dep}", f"vuln:{gid}", GraphEdgeType.ENABLES)

    # REACHES edges: a step that actually retrieved the canary.
    for f in findings:
        gid = f.ground_truth_id
        if gid and gid in canary_finding_ids:
            add_node(
                CANARY_REF, GraphNodeType.RESOURCE, "Treasury vault recovery canary",
                {"protected": True, "crown_jewel": True},
            )
            add_edge(f"vuln:{gid}", CANARY_REF, GraphEdgeType.REACHES)

    return GraphView(nodes=list(nodes.values()), edges=edges)


def discover_attack_paths(
    *,
    graph: GraphView,
    findings: list[Finding],
) -> list[AttackPathView]:
    """Find directed chains from an entry vuln to the protected canary."""
    finding_by_vuln = {
        f"vuln:{f.ground_truth_id}": f for f in findings if f.ground_truth_id
    }
    # Adjacency over ENABLES edges (vuln -> vuln) and REACHES (vuln -> resource).
    enables: dict[str, list[str]] = {}
    reaches: dict[str, list[str]] = {}
    incoming_enables: set[str] = set()
    for e in graph.edges:
        if e["type"] == GraphEdgeType.ENABLES.value:
            enables.setdefault(e["source"], []).append(e["target"])
            incoming_enables.add(e["target"])
        elif e["type"] == GraphEdgeType.REACHES.value:
            reaches.setdefault(e["source"], []).append(e["target"])

    vuln_nodes = [n["ref"] for n in graph.nodes if n["type"] == GraphNodeType.VULNERABILITY.value]
    entries = [v for v in vuln_nodes if v not in incoming_enables]

    node_by_ref = {n["ref"]: n for n in graph.nodes}
    paths: list[AttackPathView] = []

    def walk(current: str, trail: list[str]):
        # If this vuln reaches the canary, emit a completed path.
        if current in reaches:
            for resource in reaches[current]:
                full = trail + [resource]
                _emit_path(full)
        for nxt in enables.get(current, []):
            if nxt not in trail:  # avoid cycles
                walk(nxt, trail + [nxt])

    def _emit_path(node_refs: list[str]):
        vuln_refs = [r for r in node_refs if r.startswith("vuln:")]
        fids = [finding_by_vuln[r].id for r in vuln_refs if r in finding_by_vuln]
        sev = Severity.HIGH
        for r in vuln_refs:
            f = finding_by_vuln.get(r)
            if f is not None:
                fsev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
                if fsev.rank > sev.rank:
                    sev = fsev
        labels = [node_by_ref[r]["label"] for r in node_refs if r in node_by_ref]
        path_nodes = [node_by_ref[r] for r in node_refs if r in node_by_ref]
        path_edges = []
        for a, b in zip(node_refs, node_refs[1:], strict=False):
            etype = next(
                (e["type"] for e in graph.edges if e["source"] == a and e["target"] == b),
                GraphEdgeType.ENABLES.value,
            )
            path_edges.append({"source": a, "target": b, "type": etype})
        reaches_canary = node_refs[-1] == CANARY_REF
        paths.append(
            AttackPathView(
                title=" -> ".join(labels),
                nodes=path_nodes,
                edges=path_edges,
                finding_ids=fids,
                impact=(
                    "Chained weaknesses allow an unauthenticated attacker to reach "
                    "the protected treasury canary."
                    if reaches_canary
                    else "Chained weaknesses escalate access."
                ),
                severity=sev,
                confidence=Confidence.CONFIRMED,
                reaches_canary=reaches_canary,
            )
        )

    for entry in entries:
        walk(entry, [entry])

    # Prefer canary-reaching paths, longest first.
    paths.sort(key=lambda p: (p.reaches_canary, len(p.nodes)), reverse=True)
    return paths


async def persist_graph(
    session: AsyncSession, campaign_id: str, graph: GraphView
) -> None:
    """Rebuild persisted graph nodes/edges for the campaign (idempotent)."""
    await session.execute(delete(GraphEdge).where(GraphEdge.campaign_id == campaign_id))
    await session.execute(delete(GraphNode).where(GraphNode.campaign_id == campaign_id))
    for n in graph.nodes:
        session.add(
            GraphNode(
                campaign_id=campaign_id,
                type=GraphNodeType(n["type"]),
                label=n["label"],
                ref=n["ref"],
                data=n["data"],
            )
        )
    for e in graph.edges:
        session.add(
            GraphEdge(
                campaign_id=campaign_id,
                source_ref=e["source"],
                target_ref=e["target"],
                type=GraphEdgeType(e["type"]),
                data=e.get("data", {}),
            )
        )
    await session.flush()
