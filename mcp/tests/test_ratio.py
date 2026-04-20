"""Unit tests for :func:`mx_mcp.common.ratio.ratio_safe`.

The helper is tiny but its behaviour is wired into every normalised
metric — a silent change in its zero / negative handling would
cascade into mismatched benchmark samples. The tests pin down each
branch explicitly.
"""

from __future__ import annotations

import math

from mx_mcp.common.ratio import ratio_safe


# ============================================================================
# Happy path
# ============================================================================


def test_positive_ratio_is_quotient():
    assert ratio_safe(10.0, 4.0) == 2.5


def test_integer_inputs_promote_to_float():
    result = ratio_safe(9, 2)
    assert result == 4.5
    assert isinstance(result, float)


def test_equal_numerator_and_denominator_returns_one():
    assert ratio_safe(7.0, 7.0) == 1.0


def test_zero_numerator_with_positive_denominator_returns_zero():
    # Explicitly pin: 0/x where x > 0 is a well-defined 0.0, not a
    # fallback case. Only the denominator guards the fallback path.
    assert ratio_safe(0.0, 4.0) == 0.0


# ============================================================================
# Fallback path
# ============================================================================


def test_zero_denominator_uses_default_none_fallback():
    assert ratio_safe(5.0, 0.0) is None


def test_negative_denominator_uses_default_none_fallback():
    assert ratio_safe(5.0, -1.0) is None


def test_zero_denominator_with_custom_fallback():
    # A benchmark that wants "no amplification" semantics passes 0.0
    # instead of leaving the sample as an error.
    assert ratio_safe(5.0, 0.0, fallback=0.0) == 0.0


def test_negative_denominator_with_custom_fallback():
    assert ratio_safe(5.0, -2.0, fallback=1.0) == 1.0


def test_fallback_is_keyword_only():
    import pytest

    with pytest.raises(TypeError):
        # Positional fallback would be ambiguous with an extra
        # numerator argument. Guarded by the signature.
        ratio_safe(5.0, 0.0, 2.0)  # type: ignore[misc]


# ============================================================================
# Edge cases that must NOT return inf / NaN
# ============================================================================


def test_large_but_finite_ratio_is_computed_literally():
    got = ratio_safe(1e20, 1e-10)
    assert got == 1e30
    assert math.isfinite(got)


def test_very_small_denominator_returns_quotient_not_fallback():
    # Guard is ``<= 0`` — a tiny positive denominator must NOT trip
    # the fallback path. Callers relying on this (e.g. an entropy
    # ratio on a 1-byte section) would silently lose samples if we
    # widened the guard.
    got = ratio_safe(1.0, 1e-300)
    assert got is not None
    assert got > 0
