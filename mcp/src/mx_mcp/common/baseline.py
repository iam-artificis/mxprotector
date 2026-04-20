"""Unprotected-binary baseline cache — shared denominator source.

Normalised benchmarks divide protected-side measurements by the same
measurement taken from the unprotected source binary. The baseline is
a property of the source, not of protection settings — so within a
single benchmark run, every benchmark that needs it should share one
measurement per unique unprotected binary.

## Layering

* :class:`CfgBaseline` — immutable measurement record. Holds
  IDA-derived aggregates (blocks, cyclomatic, gotos, function count)
  plus the PE ``.text`` virtual size.
* :class:`ICfgBaselineProvider` — Protocol that computes a fresh
  :class:`CfgBaseline`. Concrete IDA-backed implementation lives in
  :mod:`mx_mcp.common.ida_cfg_baseline`; the split preserves
  Dependency Inversion so tests can substitute a stub.
* :class:`CfgBaselineCache` — in-process, asyncio-safe cache keyed on
  ``(canonical path, mtime_ns, size)``. Two benchmarks hitting the
  same binary run exactly one provider invocation.

## Invalidation

The cache key folds in ``mtime_ns`` and ``size``. Any rebuild that
changes either byte signature flushes the entry on the next
:meth:`CfgBaselineCache.get`. Tests that need a blank cache construct
a fresh :class:`CfgBaselineCache` — there is no global
reset-this-process API by design.

## Failure model

A provider that cannot measure (IDA missing, Hex-Rays disabled, PE
inspection failed) raises :class:`BaselineError`. The cache propagates
the exception *and does not store it* — operator-fixable failures
should retry cleanly on the next invocation.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


_LOG = logging.getLogger(__name__)


__all__ = [
    "BaselineError",
    "CfgBaseline",
    "CfgBaselineCache",
    "ICfgBaselineProvider",
]


class BaselineError(RuntimeError):
    """Raised when a CFG baseline cannot be computed for a binary."""


@dataclass(frozen=True, slots=True)
class CfgBaseline:
    """Aggregate CFG + PE measurements for one unprotected binary.

    CFG totals sum across every *matched* function. When a filter
    was applied (see :meth:`CfgBaselineCache.get`), the totals reflect
    only functions whose range covered at least one filter RVA — the
    amplification denominator that pairs semantically with the
    protected-side aggregate.

    Fields:

    * ``function_count`` — number of functions whose metrics are
      folded into the totals (filtered count when a filter was in
      effect, total when unfiltered).
    * ``total_blocks`` / ``total_cyclomatic`` / ``total_gotos`` —
      summed across the matched functions.
    * ``functions_total_bytes`` — sum of ``func.size()`` over matched
      functions. Under a filter this is "unprotected source bytes of
      exactly the functions we protected", the natural denominator for
      VM bytecode density.
    * ``text_section_size`` — raw virtual size of the ``.text``
      section. Independent of any filter (PE header reading, not
      function enumeration). Useful as a sanity check and as
      fallback denominator for unfiltered measurements.
    * ``filter_rvas`` — the filter that was in effect, or ``None``
      for unfiltered measurements. Stored for provenance so evidence
      payloads can self-describe.
    """

    binary_path: Path
    function_count: int
    total_blocks: int
    total_cyclomatic: int
    total_gotos: int
    functions_total_bytes: int
    text_section_size: int
    filter_rvas: frozenset[int] | None = None


class ICfgBaselineProvider(Protocol):
    """Computes a fresh :class:`CfgBaseline` for one unprotected binary."""

    async def measure(
        self,
        binary: Path,
        *,
        filter_rvas: frozenset[int] | None = None,
    ) -> CfgBaseline:
        """Return the baseline measurements.

        ``filter_rvas`` — optional set of input-PE RVAs. When set, the
        provider only aggregates functions whose range covers at least
        one listed RVA. This is how the normalised benchmarks pair
        the baseline with the same set of functions the protector
        defended (see ``sidecar.protected_functions``). ``None`` or
        empty means "measure every function".

        Raises :class:`BaselineError` on any measurement failure the
        cache should not retain (IDA unavailable, PE unreadable,
        Hex-Rays disabled). Callers propagate the exception so the
        benchmark surfaces it in :attr:`BenchmarkResult.errors`.
        """
        ...


@dataclass(frozen=True, slots=True)
class _Key:
    """Filesystem-derived cache key.

    ``size`` pairs with ``mtime_ns`` because some filesystems round
    mtime to the nearest second — a same-second rebuild keeping the
    mtime intact still disagrees on size in virtually every real
    case, so the combined key invalidates where mtime alone would
    silently serve stale data.

    ``filter_rvas`` distinguishes filtered from unfiltered
    measurements of the same binary — two baselines with different
    filters are legitimately distinct measurements and cannot share
    a cache entry. ``None`` is the sentinel for the unfiltered
    variant; it compares unequal to any explicit ``frozenset``.
    """

    path: str
    mtime_ns: int
    size: int
    filter_rvas: frozenset[int] | None


class CfgBaselineCache:
    """In-process asyncio-safe cache of :class:`CfgBaseline` records.

    Wraps an :class:`ICfgBaselineProvider` so every unique
    unprotected binary produces exactly one :meth:`provider.measure`
    call per cache lifetime. Concurrent :meth:`get` calls for the
    same key serialise through an :class:`asyncio.Lock`, preventing
    a burst of benchmark coroutines from triggering N parallel IDA
    runs against the same file.

    Intentionally not thread-safe — MCP benchmark runs execute under
    a single asyncio event loop and sharing this cache across threads
    is out-of-scope; making it thread-safe would require a lock
    heavier than the single-loop async use case warrants.
    """

    def __init__(self, provider: ICfgBaselineProvider) -> None:
        self._provider = provider
        self._store: dict[_Key, CfgBaseline] = {}
        self._lock = asyncio.Lock()

    async def get(
        self,
        binary: Path,
        *,
        filter_rvas: frozenset[int] | None = None,
    ) -> CfgBaseline:
        """Return the cached baseline for ``binary`` or compute fresh.

        ``filter_rvas`` forwards to :meth:`ICfgBaselineProvider.measure`
        and extends the cache key — filtered and unfiltered measurements
        of the same binary share no storage and do not invalidate each
        other.

        Raises:
            FileNotFoundError: ``binary`` missing on disk — distinct
                from provider failures so callers can treat "build
                first, measure later" scenarios explicitly.
            BaselineError: provider could not measure.
        """
        if not binary.exists():
            raise FileNotFoundError(f"baseline input missing: {binary}")

        key = self._make_key(binary, filter_rvas)
        async with self._lock:
            cached = self._store.get(key)
            if cached is not None:
                _LOG.debug(
                    "baseline cache hit: %s (filter=%s)",
                    binary.name,
                    "none" if filter_rvas is None
                    else f"{len(filter_rvas)} rva(s)",
                )
                return cached
            _LOG.info(
                "baseline cache miss: measuring %s via %s (filter=%s)",
                binary.name, type(self._provider).__name__,
                "none" if filter_rvas is None
                else f"{len(filter_rvas)} rva(s)",
            )
            measurement = await self._provider.measure(
                binary, filter_rvas=filter_rvas,
            )
            self._store[key] = measurement
            return measurement

    def __len__(self) -> int:  # diagnostic convenience for tests
        return len(self._store)

    @staticmethod
    def _make_key(
        path: Path,
        filter_rvas: frozenset[int] | None,
    ) -> _Key:
        stat = path.stat()
        return _Key(
            path=str(path.resolve()),
            mtime_ns=stat.st_mtime_ns,
            size=stat.st_size,
            filter_rvas=filter_rvas,
        )
