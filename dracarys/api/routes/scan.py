from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException

from dracarys.domain.schemas import ScanRequest
from dracarys.scanner import ScanConfig
from dracarys.scanner import report as scan_report
from dracarys.scanner.runner import authorize, run_scan

router = APIRouter(tags=["scanner"])


@router.post("/api/scan")
async def run_generic_scan(payload: ScanRequest) -> dict:
    """Scan an authorized HTTP target with the generic DAST engine (synchronous).

    Loopback targets are allowed; any other target requires ``authorized: true``.
    """
    auth = authorize(payload.url, payload.authorized)
    if not auth.ok:
        raise HTTPException(status_code=422, detail=auth.reason)
    config = ScanConfig(
        active=payload.active, include_time_based=payload.include_time_based,
        max_pages=payload.max_pages, auth_headers=payload.auth_headers,
    )
    result = await run_scan(payload.url, config, max_requests=payload.max_requests)
    return json.loads(scan_report.to_json(result))
