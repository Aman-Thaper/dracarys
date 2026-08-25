"""Score a completed campaign against the lab's objective ground truth.

Metrics compare what DRACARYS actually persisted (findings, evidence, attack
paths, retests) to the known answer key in ``lab.ground_truth`` — never against
model self-assessment.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from sqlalchemy import select

from dracarys.db.base import Database
from dracarys.db.models import (
    AttackPath,
    Finding,
    Hypothesis,
    Remediation,
    Retest,
)
from dracarys.domain.enums import HypothesisStatus, RetestResult
from lab.ground_truth import GROUND_TRUTH


@dataclass
class EvaluationMetrics:
    expected: int
    detected: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    validation_rate: float          # confirmed / (confirmed + disproven + inconclusive)
    evidence_completeness: float     # findings with >=1 evidence / findings
    attack_chain_discovered: bool
    attack_paths_to_canary: int
    remediation_success: float       # remediations / findings
    retest_success: float            # fix_verified / retests
    regression_rate: float           # fix_failed / retests
    detected_ids: list[str] = field(default_factory=list)
    missed_ids: list[str] = field(default_factory=list)
    false_positive_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _safe_div(n: int, d: int) -> float:
    return round(n / d, 4) if d else 0.0


async def evaluate_campaign(db: Database, campaign_id: str) -> EvaluationMetrics:
    async with db.session_factory() as s:
        findings = (await s.execute(
            select(Finding).where(Finding.campaign_id == campaign_id)
        )).scalars().all()
        hypotheses = (await s.execute(
            select(Hypothesis).where(Hypothesis.campaign_id == campaign_id)
        )).scalars().all()
        paths = (await s.execute(
            select(AttackPath).where(AttackPath.campaign_id == campaign_id)
        )).scalars().all()
        retests = (await s.execute(
            select(Retest).where(Retest.campaign_id == campaign_id)
        )).scalars().all()
        remediations = (await s.execute(
            select(Remediation).join(Finding, Remediation.finding_id == Finding.id)
            .where(Finding.campaign_id == campaign_id)
        )).scalars().all()

    expected = set(GROUND_TRUTH.keys())
    detected = {f.ground_truth_id for f in findings if f.ground_truth_id}
    tp = detected & expected
    fp = detected - expected
    fn = expected - detected

    precision = _safe_div(len(tp), len(tp) + len(fp))
    recall = _safe_div(len(tp), len(tp) + len(fn))
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    decided = [h for h in hypotheses if h.status in {
        HypothesisStatus.CONFIRMED, HypothesisStatus.DISPROVEN, HypothesisStatus.INCONCLUSIVE
    }]
    confirmed = [h for h in hypotheses if h.status == HypothesisStatus.CONFIRMED]
    validation_rate = _safe_div(len(confirmed), len(decided))

    with_ev = [f for f in findings if f.evidence_refs]
    evidence_completeness = _safe_div(len(with_ev), len(findings))

    canary_paths = [p for p in paths if p.reaches_canary]
    fixed = [r for r in retests if r.result == RetestResult.FIX_VERIFIED]
    failed = [r for r in retests if r.result == RetestResult.FIX_FAILED]

    return EvaluationMetrics(
        expected=len(expected),
        detected=len(detected),
        true_positives=len(tp),
        false_positives=len(fp),
        false_negatives=len(fn),
        precision=precision,
        recall=recall,
        f1=f1,
        validation_rate=validation_rate,
        evidence_completeness=evidence_completeness,
        attack_chain_discovered=len(canary_paths) > 0,
        attack_paths_to_canary=len(canary_paths),
        remediation_success=_safe_div(len(remediations), len(findings)),
        retest_success=_safe_div(len(fixed), len(retests)),
        regression_rate=_safe_div(len(failed), len(retests)),
        detected_ids=sorted(detected),
        missed_ids=sorted(fn),
        false_positive_ids=sorted(fp),
    )
