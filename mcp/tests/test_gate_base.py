"""Unit tests for ``common.gate_base``.

Covers:

1. ``GateOutcome.is_blocking`` — only FAIL counts; tier scope respected.
2. Registration validation — duplicate names, missing class attrs,
   wrong base class are all rejected at decorator time.
3. ``register_gate`` returns the class so ``@register_gate`` chains
   cleanly.
"""

from __future__ import annotations

import pytest

from mx_mcp.common.benchmark_base import (
    AggregateStats,
    MetricDirection,
    MetricResult,
)
from mx_mcp.common.gate_base import (
    GateLevel,
    GateOutcome,
    GateScope,
    IGate,
    register_gate,
)
from mx_mcp.common.gate_base import _REGISTRY as _GATE_REGISTRY


# ============================================================================
# Outcome.is_blocking
# ============================================================================


def _outcome(*, level: GateLevel, scope: GateScope) -> GateOutcome:
    return GateOutcome(
        gate="t", benchmark="b", metric="m",
        level=level, scope=scope,
        threshold_repr="x", observed=0.0, message="",
    )


def test_pass_outcome_never_blocks():
    o = _outcome(level=GateLevel.PASS, scope=GateScope.FAST)
    assert o.is_blocking("fast") is False
    assert o.is_blocking("slow") is False


def test_fail_outcome_blocks_matching_tier():
    o = _outcome(level=GateLevel.FAIL, scope=GateScope.FAST)
    assert o.is_blocking("fast") is True
    assert o.is_blocking("slow") is False


def test_fail_outcome_with_any_scope_blocks_every_tier():
    o = _outcome(level=GateLevel.FAIL, scope=GateScope.ANY)
    assert o.is_blocking("fast") is True
    assert o.is_blocking("slow") is True


def test_warn_and_skipped_never_block():
    for level in (GateLevel.WARN, GateLevel.SKIPPED):
        o = _outcome(level=level, scope=GateScope.ANY)
        assert o.is_blocking("fast") is False
        assert o.is_blocking("slow") is False


# ============================================================================
# Registration
# ============================================================================


def _empty_metric() -> MetricResult:
    return MetricResult(
        name="m",
        direction=MetricDirection.LOWER_BETTER,
        samples=[],
        aggregate=AggregateStats(
            p10=None, p50=None, p90=None, mean=None, stddev=None,
            n_samples=0, n_errors=0,
        ),
    )


def _stash_registry():
    """Snapshot + restore the registry around a test that mutates it."""
    return list(_GATE_REGISTRY)


def _restore_registry(snapshot: list[type[IGate]]) -> None:
    _GATE_REGISTRY.clear()
    _GATE_REGISTRY.extend(snapshot)


def test_register_gate_adds_class_to_registry():
    snap = _stash_registry()
    try:
        @register_gate
        class _G(IGate):
            name = "test_register_gate_unique"
            description = "x"
            benchmark = "b"
            metric = "m"
            scope = GateScope.FAST

            def evaluate(self, mr):
                return _outcome(level=GateLevel.PASS, scope=self.scope)

        assert _G in _GATE_REGISTRY
    finally:
        _restore_registry(snap)


def test_register_gate_rejects_non_subclass():
    class _NotAGate:
        name = "_not_a_gate"
        description = "x"
        benchmark = "b"
        metric = "m"
        scope = GateScope.FAST

    with pytest.raises(TypeError, match="must subclass IGate"):
        register_gate(_NotAGate)  # type: ignore[arg-type]


def test_register_gate_rejects_missing_attr():
    snap = _stash_registry()
    try:
        with pytest.raises(TypeError, match="missing required class attr"):
            @register_gate
            class _G(IGate):
                name = "test_missing_attr"
                # description missing
                benchmark = "b"
                metric = "m"
                scope = GateScope.FAST

                def evaluate(self, mr):  # pragma: no cover
                    return _outcome(level=GateLevel.PASS, scope=self.scope)
    finally:
        _restore_registry(snap)


def test_register_gate_rejects_duplicate_name():
    snap = _stash_registry()
    try:
        @register_gate
        class _G1(IGate):
            name = "test_dup_collision_xyz"
            description = "x"
            benchmark = "b"
            metric = "m"
            scope = GateScope.FAST

            def evaluate(self, mr):
                return _outcome(level=GateLevel.PASS, scope=self.scope)

        with pytest.raises(ValueError, match="name collision"):
            @register_gate
            class _G2(IGate):
                name = "test_dup_collision_xyz"   # same as _G1
                description = "x"
                benchmark = "b"
                metric = "m2"
                scope = GateScope.FAST

                def evaluate(self, mr):  # pragma: no cover
                    return _outcome(level=GateLevel.PASS, scope=self.scope)
    finally:
        _restore_registry(snap)


def test_register_gate_returns_class():
    """Decorator return value must be the class itself for chaining."""
    snap = _stash_registry()
    try:
        @register_gate
        class _G(IGate):
            name = "test_decorator_return_xyz"
            description = "x"
            benchmark = "b"
            metric = "m"
            scope = GateScope.FAST

            def evaluate(self, mr):
                return _outcome(level=GateLevel.PASS, scope=self.scope)

        # The decorator returned _G, so it is callable as a class.
        instance = _G()
        assert isinstance(instance, IGate)
    finally:
        _restore_registry(snap)
