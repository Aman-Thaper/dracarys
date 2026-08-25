"""Broken access control (IDOR/BOLA) via differential testing.

Requires two identities. For each URL known to belong to identity 2, identity 1
(a different user) attempts the same request; if it succeeds with equivalent
content, object-level authorization is missing.
"""
from __future__ import annotations

from dracarys.agents.context import LabeledExchange
from dracarys.domain.enums import Confidence, VulnCategory
from dracarys.scanner.detectors.base import SiteDetector, make_finding
from dracarys.scanner.oracles import similarity

_AUTH_MARKERS = ("login", "sign in", "unauthorized", "forbidden", "access denied")


class IdorDifferentialDetector:
    id = "idor"

    async def run(self, ctx):
        cfg = ctx.config
        if not cfg.second_identity_headers or not cfg.protected_urls:
            return []
        findings = []
        for url in cfg.protected_urls:
            owner = await ctx.tool.send("GET", url, headers=cfg.second_identity_headers,
                                        note="IDOR: owner baseline")
            attacker = await ctx.tool.send("GET", url, headers=cfg.auth_headers,
                                           note="IDOR: cross-identity access")
            if owner.status_code != 200 or attacker.status_code != 200:
                continue
            body = attacker.body_text.lower()
            looks_like_auth_wall = any(m in body for m in _AUTH_MARKERS)
            if not looks_like_auth_wall and similarity(owner.body_text, attacker.body_text) >= 0.9:
                findings.append(make_finding(
                    detector=self.id, category=VulnCategory.IDOR,
                    title="Broken object-level authorization (IDOR)", url=url, method="GET",
                    detail="A second identity retrieved another user's object with "
                           "content equivalent to the owner's response.",
                    evidence=[LabeledExchange("owner response", owner),
                              LabeledExchange("attacker (cross-identity) response", attacker)],
                    confidence=Confidence.CONFIRMED, dedup_key=f"idor:{url}",
                ))
        return findings


ACCESS_DETECTORS: list[SiteDetector] = [IdorDifferentialDetector()]
