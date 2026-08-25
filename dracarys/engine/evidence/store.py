"""Evidence store — turns captured tool exchanges into immutable proof records.

A finding must be able to answer "why do you believe this exists?" with stored
evidence (hashes, request/response metadata), not model-generated prose.
"""
from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from dracarys.db.models import Evidence
from dracarys.tools.base import HttpExchange


class EvidenceStore:
    def __init__(self, session: AsyncSession, campaign_id: str) -> None:
        self.session = session
        self.campaign_id = campaign_id

    async def record_exchange(
        self,
        exchange: HttpExchange,
        *,
        summary: str,
        tool: str = "http",
        kind: str = "http_exchange",
        observation_id: str | None = None,
        test_run_id: str | None = None,
        finding_id: str | None = None,
    ) -> Evidence:
        payload = exchange.evidence_payload()
        evidence = Evidence(
            campaign_id=self.campaign_id,
            kind=kind,
            tool=tool,
            summary=summary,
            request_meta=payload["request"],
            response_meta=exchange.response,
            content={
                "body_preview": payload["body_preview"],
                "body_truncated": payload["body_truncated"],
                "policy_reason": exchange.policy_reason,
                "elapsed_ms": exchange.elapsed_ms,
                "tool_status": exchange.status.value,
            },
            sha256=exchange.sha256,
            observation_id=observation_id,
            test_run_id=test_run_id,
            finding_id=finding_id,
            reproducible=True,
        )
        self.session.add(evidence)
        await self.session.flush()
        return evidence
