"""Shared state and result types for attack modules.

AttackContext carries artifacts *discovered* during a campaign (leaked creds,
session tokens, the canary) from one module to the next — this is how a chain
forms from real behavior rather than hardcoded links.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from dracarys.domain.enums import Severity, TestOutcome, VulnCategory
from dracarys.tools.base import HttpExchange


@dataclass
class AttackContext:
    canary_token: str
    leaked_credentials: dict | None = None       # {"username":..., "password":...}
    tokens: dict[str, str] = field(default_factory=dict)  # username -> bearer token
    identities: dict[str, dict] = field(default_factory=dict)  # username -> {role,...}
    discovered: dict = field(default_factory=dict)
    reached_canary: bool = False
    canary_via: list[str] = field(default_factory=list)

    def any_non_admin_token(self) -> tuple[str, str] | None:
        for username, token in self.tokens.items():
            if self.identities.get(username, {}).get("role") != "admin":
                return username, token
        # fall back to any token
        for username, token in self.tokens.items():
            return username, token
        return None

    def merge(self, extracted: dict) -> None:
        creds = extracted.get("leaked_credentials")
        if creds:
            self.leaked_credentials = creds
        for username, token in extracted.get("tokens", {}).items():
            self.tokens[username] = token
        for username, ident in extracted.get("identities", {}).items():
            self.identities[username] = ident
        self.discovered.update(extracted.get("discovered", {}))
        if extracted.get("reached_canary"):
            self.reached_canary = True
        for via in extracted.get("canary_via", []):
            if via not in self.canary_via:
                self.canary_via.append(via)


@dataclass
class LabeledExchange:
    label: str
    exchange: HttpExchange


@dataclass
class AttackOutcome:
    module_id: str                 # ground-truth candidate (e.g. LAB-IDOR-001)
    category: VulnCategory
    severity: Severity
    outcome: TestOutcome
    title: str
    hypothesis: str
    success_criteria: str
    detail: str
    root_cause: str = ""
    impact: str = ""
    affected_asset: str = ""
    exchanges: list[LabeledExchange] = field(default_factory=list)
    extracted: dict = field(default_factory=dict)
    reached_canary: bool = False

    @property
    def confirmed(self) -> bool:
        return self.outcome == TestOutcome.CONFIRMED
