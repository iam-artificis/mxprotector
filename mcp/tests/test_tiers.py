"""Unit tests for common.tiers: Tier enum + parse + filter."""

from __future__ import annotations

import pytest

from mx_mcp.common.benchmark_base import IBenchmark
from mx_mcp.common.tiers import (
    TIER_BUDGET_SECONDS,
    Tier,
    filter_by_tier,
    parse_tier,
)


class _FastBench(IBenchmark):
    name = "f"; description = "x"; category = "cff"; tier = "fast"
    async def run(self, corpus, session): raise NotImplementedError  # noqa: E701


class _SlowBench(IBenchmark):
    name = "s"; description = "x"; category = "vm"; tier = "slow"
    async def run(self, corpus, session): raise NotImplementedError  # noqa: E701


class _NightlyBench(IBenchmark):
    name = "n"; description = "x"; category = "packer"; tier = "nightly"
    async def run(self, corpus, session): raise NotImplementedError  # noqa: E701


# ============================================================================
# parse_tier
# ============================================================================


@pytest.mark.parametrize("label,expected", [
    ("fast", Tier.FAST),
    ("FAST", Tier.FAST),
    (" slow ", Tier.SLOW),
    ("Nightly", Tier.NIGHTLY),
])
def test_parse_tier_accepts_valid(label: str, expected: Tier):
    assert parse_tier(label) is expected


def test_parse_tier_rejects_unknown():
    with pytest.raises(ValueError, match="unknown tier"):
        parse_tier("ultra")


# ============================================================================
# filter_by_tier
# ============================================================================


def test_filter_by_tier_selects_matching():
    benchmarks = [_FastBench, _SlowBench, _NightlyBench]
    assert filter_by_tier(benchmarks, Tier.FAST) == [_FastBench]
    assert filter_by_tier(benchmarks, Tier.SLOW) == [_SlowBench]
    assert filter_by_tier(benchmarks, Tier.NIGHTLY) == [_NightlyBench]


def test_filter_by_tier_empty_when_no_match():
    assert filter_by_tier([_FastBench], Tier.SLOW) == []


# ============================================================================
# Budgets
# ============================================================================


def test_budget_table_has_entry_for_every_tier():
    # Every enum variant must have a budget so new tiers are caught at
    # review time when the table is updated alongside the enum.
    for tier in Tier:
        assert tier in TIER_BUDGET_SECONDS
        assert TIER_BUDGET_SECONDS[tier] > 0


def test_budget_ordering():
    # Budgets strictly increase with tier heaviness.
    assert (
        TIER_BUDGET_SECONDS[Tier.FAST]
        < TIER_BUDGET_SECONDS[Tier.SLOW]
        < TIER_BUDGET_SECONDS[Tier.NIGHTLY]
    )
