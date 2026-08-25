from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.api.deps import get_session
from dracarys.db.models import Campaign, Evidence, Finding, Retest
from dracarys.domain.enums import CampaignState, RetestResult, Severity

router = APIRouter(tags=["metrics"])


@router.get("/api/metrics")
async def platform_metrics(session: AsyncSession = Depends(get_session)) -> dict:
    """Operational metrics aggregated across all campaigns (structured, DB-derived)."""
    campaigns = (await session.execute(select(Campaign))).scalars().all()
    by_state = {s.value: 0 for s in CampaignState}
    total_requests = 0
    for c in campaigns:
        state = c.state if isinstance(c.state, CampaignState) else CampaignState(c.state)
        by_state[state.value] += 1
        total_requests += c.requests_made

    findings = (await session.execute(select(Finding))).scalars().all()
    by_severity = {s.value: 0 for s in Severity}
    for f in findings:
        sev = f.severity if isinstance(f.severity, Severity) else Severity(f.severity)
        by_severity[sev.value] += 1

    evidence_count = (await session.execute(select(func.count()).select_from(Evidence))).scalar() or 0
    retests = (await session.execute(select(Retest))).scalars().all()
    verified = sum(1 for r in retests if r.result == RetestResult.FIX_VERIFIED)

    return {
        "campaigns_total": len(campaigns),
        "campaigns_by_state": by_state,
        "findings_total": len(findings),
        "findings_by_severity": by_severity,
        "evidence_records": int(evidence_count),
        "total_requests_made": total_requests,
        "retests_total": len(retests),
        "fixes_verified": verified,
        "fix_verification_rate": round(verified / len(retests), 4) if retests else 0.0,
    }
