"""Explicit, persisted campaign lifecycle.

Transitions are validated so a campaign can only move along the defined pipeline
(or into a control/terminal state). State is persisted after every transition, so
progress survives a process restart.
"""
from __future__ import annotations

from dracarys.db.base import utcnow
from dracarys.db.models import Campaign
from dracarys.domain.enums import CampaignState as S

# Linear happy-path pipeline plus control transitions.
_PIPELINE = [
    S.CREATED, S.SCOPING, S.RECON, S.ATTACK_PLANNING, S.TESTING, S.VALIDATION,
    S.ATTACK_CHAIN_ANALYSIS, S.REPORTING, S.REMEDIATION, S.RETEST, S.COMPLETE,
]

_ALLOWED: dict[S, set[S]] = {}
for _i, _state in enumerate(_PIPELINE[:-1]):
    _ALLOWED.setdefault(_state, set()).add(_PIPELINE[_i + 1])

# From any active (non-terminal) state you may fail, cancel, or pause.
_CONTROL = {S.FAILED, S.CANCELLED, S.PAUSED}
for _state in _PIPELINE:
    if _state != S.COMPLETE:
        _ALLOWED.setdefault(_state, set()).update(_CONTROL)

# A paused campaign may resume to where it left off or terminate.
_ALLOWED[S.PAUSED] = set(_PIPELINE) | {S.CANCELLED, S.FAILED}


class InvalidTransition(Exception):
    pass


def can_transition(current: S, target: S) -> bool:
    if current == target:
        return True
    return target in _ALLOWED.get(current, set())


def transition(campaign: Campaign, target: S) -> None:
    current = campaign.state if isinstance(campaign.state, S) else S(campaign.state)
    if not can_transition(current, target):
        raise InvalidTransition(f"{current.value} -> {target.value} is not allowed")
    campaign.state = target
    if target == S.SCOPING and campaign.started_at is None:
        campaign.started_at = utcnow()
    if target in {S.COMPLETE, S.FAILED, S.CANCELLED}:
        campaign.completed_at = utcnow()
