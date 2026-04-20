"""Safe ratio helper — guards against zero / negative denominators.

Normalised metrics in the measurement suite divide a *protected*
measurement by its *unprotected* baseline to yield a corpus-independent
amplification factor. A zero or negative denominator signals a
degenerate baseline (e.g. an input with an empty ``.text`` or a build
that produced zero microcode blocks) where the ratio is undefined.

Returning :obj:`None` rather than raising keeps benchmarks fail-closed:
the resulting sample lands with ``value=None``, which
:class:`mx_mcp.common.benchmark_base.AggregateStats` counts as an error
sample instead of crashing the whole benchmark run. A caller that
wants "no amplification" semantics instead can pass ``fallback=0.0``.
"""

from __future__ import annotations

__all__ = ["ratio_safe"]


def ratio_safe(
    numerator: float,
    denominator: float,
    *,
    fallback: float | None = None,
) -> float | None:
    """Return ``numerator / denominator`` or ``fallback`` on degenerate input.

    ``denominator <= 0`` triggers the fallback path — zero is the
    pathological case and negative denominators never arise in metric
    aggregations but are rejected for safety (a future refactor that
    fed a signed delta into this helper should surface as
    ``None`` / ``fallback`` rather than a spurious negative
    amplification).
    """
    if denominator <= 0:
        return fallback
    return numerator / denominator
