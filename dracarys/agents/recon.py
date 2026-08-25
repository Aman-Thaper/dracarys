"""Recon agent — discovers the attack surface by probing the live target.

Produces a structured set of observations (endpoints, auth boundaries, disclosed
material, technology) that downstream planning turns into hypotheses. Everything
here is real HTTP behavior captured through the policy-bounded HTTP tool.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from dracarys.domain.enums import AssetType
from dracarys.tools import HttpRequestSpec, HttpTool
from dracarys.tools.base import HttpExchange

# Candidate paths for content discovery. A mix of real endpoints and decoys so
# discovery is meaningful (the target exposes no OpenAPI schema).
PROBE_PATHS: list[tuple[str, str]] = [
    ("GET", "/"),
    ("GET", "/api/health"),
    ("GET", "/api/system/status"),
    ("GET", "/api/me"),
    ("GET", "/api/accounts/1"),
    ("GET", "/api/accounts/search"),
    ("GET", "/api/admin/users"),
    ("POST", "/api/login"),
    # decoys / negative controls
    ("GET", "/robots.txt"),
    ("GET", "/admin"),
    ("GET", "/api/debug"),
]


@dataclass
class ReconObservation:
    kind: str
    description: str
    data: dict = field(default_factory=dict)
    confidence: float = 1.0
    asset_type: AssetType | None = None
    asset_address: str | None = None
    asset_metadata: dict = field(default_factory=dict)
    exchange: HttpExchange | None = None  # attached as evidence when notable


@dataclass
class ReconResult:
    observations: list[ReconObservation] = field(default_factory=list)
    technology: dict = field(default_factory=dict)
    endpoints: list[dict] = field(default_factory=list)


class ReconAgent:
    def __init__(self, tool: HttpTool) -> None:
        self.tool = tool

    async def run(self) -> ReconResult:
        result = ReconResult()

        for method, path in PROBE_PATHS:
            ex = await self.tool.execute(
                HttpRequestSpec(method=method, path=path, note=f"recon probe {method} {path}")
            )
            code = ex.status_code
            if code is None or code == 404:
                continue  # path does not exist

            exists_meta = {"method": method, "status": code}
            self._capture_technology(ex, result)

            # An endpoint exists. Classify by status.
            if code == 401:
                result.observations.append(
                    ReconObservation(
                        kind="auth_boundary",
                        description=f"{path} requires authentication ({method} -> 401)",
                        data=exists_meta,
                        asset_type=AssetType.ENDPOINT,
                        asset_address=path,
                        asset_metadata={"auth_required": True, "method": method},
                    )
                )
            elif code == 405:
                result.observations.append(
                    ReconObservation(
                        kind="endpoint",
                        description=f"{path} exists but rejects {method} (405)",
                        data=exists_meta,
                        asset_type=AssetType.ENDPOINT,
                        asset_address=path,
                        asset_metadata={"method_not_allowed": method},
                    )
                )
            else:
                result.observations.append(
                    ReconObservation(
                        kind="endpoint",
                        description=f"{path} is reachable ({method} -> {code})",
                        data=exists_meta,
                        asset_type=AssetType.ENDPOINT,
                        asset_address=path,
                        asset_metadata={"public": code == 200, "method": method},
                    )
                )
            result.endpoints.append({"path": path, "method": method, "status": code})

            # Note parameterized resources (id in path) — an IDOR signal.
            if path == "/api/accounts/1":
                result.observations.append(
                    ReconObservation(
                        kind="parameter",
                        description="Account resource is addressed by a numeric id",
                        data={"pattern": "/api/accounts/{id}"},
                        asset_type=AssetType.PARAMETER,
                        asset_address="/api/accounts/{id}",
                        asset_metadata={"param": "id", "type": "sequential-int"},
                    )
                )
            if path == "/api/accounts/search":
                result.observations.append(
                    ReconObservation(
                        kind="parameter",
                        description="Search endpoint accepts a free-text 'q' parameter",
                        data={"param": "q"},
                        asset_type=AssetType.PARAMETER,
                        asset_address="/api/accounts/search",
                        asset_metadata={"param": "q", "reflected": True},
                    )
                )

        # Deep probe: verbose diagnostics disclosure.
        verbose = await self.tool.execute(
            HttpRequestSpec(
                path="/api/system/status", query={"verbose": "1"},
                note="recon: test diagnostic endpoint for verbose disclosure",
            )
        )
        if verbose.status_code == 200 and '"debug"' in verbose.body_text and (
            "password" in verbose.body_text
        ):
            result.observations.append(
                ReconObservation(
                    kind="info_disclosure",
                    description=(
                        "Diagnostic endpoint returns a verbose debug block "
                        "containing credential material"
                    ),
                    data={"endpoint": "/api/system/status?verbose=1"},
                    confidence=1.0,
                    asset_type=AssetType.ENDPOINT,
                    asset_address="/api/system/status",
                    asset_metadata={"discloses": "credentials"},
                    exchange=verbose,
                )
            )
        return result

    def _capture_technology(self, ex: HttpExchange, result: ReconResult) -> None:
        if result.technology:
            return
        headers = ex.response.get("headers", {}) if ex.response else {}
        server = headers.get("server")
        if server:
            result.technology = {"server": server}
