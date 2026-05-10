"""Tests for the per-session sampling budget."""

from __future__ import annotations

import pytest

from mcp_demo.shared.sampling_policy import (
    SamplingBudget,
    SamplingBudgetExceeded,
)


def test_budget_starts_at_full_capacity() -> None:
    budget = SamplingBudget(per_session_max_requests=3)
    assert budget.remaining(session_id="s") == 3


def test_budget_decrements_on_consume() -> None:
    budget = SamplingBudget(per_session_max_requests=3)
    budget.consume(session_id="s", cost=1)
    assert budget.remaining(session_id="s") == 2


def test_budget_blocks_on_overrun() -> None:
    budget = SamplingBudget(per_session_max_requests=2)
    budget.consume(session_id="s", cost=1)
    budget.consume(session_id="s", cost=1)
    with pytest.raises(SamplingBudgetExceeded):
        budget.consume(session_id="s", cost=1)


def test_budget_is_per_session() -> None:
    budget = SamplingBudget(per_session_max_requests=1)
    budget.consume(session_id="alice", cost=1)
    # Bob still has full budget.
    budget.consume(session_id="bob", cost=1)


def test_consume_with_zero_or_negative_cost_is_refused() -> None:
    budget = SamplingBudget(per_session_max_requests=2)
    with pytest.raises(ValueError):
        budget.consume(session_id="s", cost=0)
    with pytest.raises(ValueError):
        budget.consume(session_id="s", cost=-1)
