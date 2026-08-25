"""Unit tests for the campaign state machine."""
import pytest

from dracarys.db.models import Campaign
from dracarys.domain.enums import CampaignState as S
from dracarys.engine.orchestrator.state_machine import (
    InvalidTransition,
    can_transition,
    transition,
)


def test_happy_path_transitions_allowed():
    seq = [S.CREATED, S.SCOPING, S.RECON, S.ATTACK_PLANNING, S.TESTING, S.VALIDATION,
           S.ATTACK_CHAIN_ANALYSIS, S.REPORTING, S.REMEDIATION, S.RETEST, S.COMPLETE]
    for a, b in zip(seq, seq[1:], strict=False):
        assert can_transition(a, b), f"{a}->{b} should be allowed"


def test_cannot_skip_phases():
    assert not can_transition(S.CREATED, S.TESTING)
    assert not can_transition(S.RECON, S.COMPLETE)


def test_any_active_can_fail_cancel_pause():
    for state in [S.RECON, S.TESTING, S.REMEDIATION]:
        for control in [S.FAILED, S.CANCELLED, S.PAUSED]:
            assert can_transition(state, control)


def test_paused_can_resume_to_pipeline():
    assert can_transition(S.PAUSED, S.RECON)
    assert can_transition(S.PAUSED, S.TESTING)


def test_transition_sets_timestamps():
    c = Campaign(target_id="t", state=S.CREATED)
    transition(c, S.SCOPING)
    assert c.state == S.SCOPING and c.started_at is not None
    # advance to a terminal state
    c.state = S.RETEST
    transition(c, S.COMPLETE)
    assert c.completed_at is not None


def test_invalid_transition_raises():
    c = Campaign(target_id="t", state=S.COMPLETE)
    with pytest.raises(InvalidTransition):
        transition(c, S.RECON)
