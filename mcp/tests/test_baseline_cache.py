"""Unit tests for :class:`mx_mcp.common.baseline.CfgBaselineCache`.

Every measurement in the suite ultimately depends on the cache
behaving the way the benchmarks assume: one measurement per unique
binary, invalidation when the binary changes on disk, and errors
that do not silently stick around. These tests pin each property
against a stub provider so no real IDA is involved.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest

from mx_mcp.common.baseline import (
    BaselineError,
    CfgBaseline,
    CfgBaselineCache,
)


# ============================================================================
# Stub provider — counts calls, returns a deterministic baseline
# ============================================================================


class _StubProvider:
    """Captures every ``measure`` call for inspection by tests.

    Yields control via ``asyncio.sleep(0)`` to exercise the cache's
    lock under concurrent :meth:`CfgBaselineCache.get` calls — without
    a yield, the runtime can serialise purely through the event-loop
    pre-emption rules and the lock's effect is invisible.
    """

    def __init__(
        self,
        *,
        fn_count: int = 10,
        blocks: int = 50,
        cyc: int = 30,
        gotos: int = 5,
        fn_bytes: int = 2048,
        text_size: int = 4096,
        raise_error: bool = False,
    ) -> None:
        self.calls: list[tuple[Path, frozenset[int] | None]] = []
        self._fn_count = fn_count
        self._blocks = blocks
        self._cyc = cyc
        self._gotos = gotos
        self._fn_bytes = fn_bytes
        self._text_size = text_size
        self._raise_error = raise_error

    async def measure(
        self,
        binary: Path,
        *,
        filter_rvas: frozenset[int] | None = None,
    ) -> CfgBaseline:
        self.calls.append((binary, filter_rvas))
        await asyncio.sleep(0)
        if self._raise_error:
            raise BaselineError(f"stub error for {binary.name}")
        return CfgBaseline(
            binary_path=binary,
            function_count=self._fn_count,
            total_blocks=self._blocks,
            total_cyclomatic=self._cyc,
            total_gotos=self._gotos,
            functions_total_bytes=self._fn_bytes,
            text_section_size=self._text_size,
            filter_rvas=filter_rvas,
        )


def _write_binary(path: Path, content: bytes = b"MZsome-bytes") -> Path:
    path.write_bytes(content)
    return path


# ============================================================================
# Happy path
# ============================================================================


def test_first_get_calls_provider(tmp_path: Path):
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    result = asyncio.run(cache.get(binary))

    assert isinstance(result, CfgBaseline)
    assert result.binary_path == binary
    assert result.function_count == 10
    assert result.total_blocks == 50
    assert len(provider.calls) == 1
    assert len(cache) == 1


def test_second_get_hits_cache(tmp_path: Path):
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> tuple[CfgBaseline, CfgBaseline]:
        r1 = await cache.get(binary)
        r2 = await cache.get(binary)
        return r1, r2

    r1, r2 = asyncio.run(_run())

    assert r1 is r2  # dataclass instance reused from the cache store
    assert len(provider.calls) == 1


def test_different_binaries_measured_independently(tmp_path: Path):
    a = _write_binary(tmp_path / "a.exe", b"MZaaa")
    b = _write_binary(tmp_path / "b.exe", b"MZbbb")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> None:
        await cache.get(a)
        await cache.get(b)

    asyncio.run(_run())

    assert [call[0] for call in provider.calls] == [a, b]
    assert len(cache) == 2


# ============================================================================
# Invalidation
# ============================================================================


def test_mtime_change_invalidates_cache(tmp_path: Path):
    """Writing the file again with a different mtime must bypass the cache."""
    binary = _write_binary(tmp_path / "foo.exe", b"MZver1")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    asyncio.run(cache.get(binary))
    assert len(provider.calls) == 1

    # Advance mtime by one full second so platforms with 1 s mtime
    # resolution still see the bump.
    stat = binary.stat()
    os.utime(binary, ns=(stat.st_mtime_ns + 10_000_000_000,
                         stat.st_mtime_ns + 10_000_000_000))

    asyncio.run(cache.get(binary))
    assert len(provider.calls) == 2


def test_size_change_invalidates_cache(tmp_path: Path):
    """Same-mtime rebuild with a different size must bypass the cache."""
    binary = _write_binary(tmp_path / "foo.exe", b"MZshort")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    asyncio.run(cache.get(binary))
    original_stat = binary.stat()

    # Rewrite with a different byte signature (different size), then
    # restore the mtime so only ``size`` has changed in the cache key.
    binary.write_bytes(b"MZlonger-content-now")
    os.utime(binary, ns=(original_stat.st_mtime_ns, original_stat.st_mtime_ns))

    asyncio.run(cache.get(binary))
    assert len(provider.calls) == 2


def test_unchanged_file_stays_cached_after_many_reads(tmp_path: Path):
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> None:
        for _ in range(20):
            await cache.get(binary)

    asyncio.run(_run())
    assert len(provider.calls) == 1


# ============================================================================
# Failure modes
# ============================================================================


def test_missing_binary_raises_file_not_found(tmp_path: Path):
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    with pytest.raises(FileNotFoundError, match="baseline input missing"):
        asyncio.run(cache.get(tmp_path / "does_not_exist.exe"))

    assert provider.calls == []
    assert len(cache) == 0


def test_provider_error_propagates_and_is_not_cached(tmp_path: Path):
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider(raise_error=True)
    cache = CfgBaselineCache(provider)

    with pytest.raises(BaselineError, match="stub error"):
        asyncio.run(cache.get(binary))
    assert len(provider.calls) == 1
    assert len(cache) == 0  # failure NOT stored

    # Second attempt after the operator "fixes" whatever was wrong —
    # provider stops raising. Cache must retry cleanly instead of
    # replaying the stale failure.
    provider_fixed = _StubProvider(raise_error=False)
    cache2 = CfgBaselineCache(provider_fixed)
    result = asyncio.run(cache2.get(binary))
    assert isinstance(result, CfgBaseline)
    assert len(provider_fixed.calls) == 1


# ============================================================================
# Concurrency
# ============================================================================


def test_concurrent_get_runs_provider_once(tmp_path: Path):
    """Two coroutines hitting the same key serialise through the lock
    — the provider records exactly one call even under ``asyncio.gather``.
    """
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> tuple[CfgBaseline, CfgBaseline]:
        return await asyncio.gather(cache.get(binary), cache.get(binary))

    r1, r2 = asyncio.run(_run())
    assert r1 is r2
    assert len(provider.calls) == 1


def test_concurrent_get_on_distinct_binaries_runs_provider_twice(tmp_path: Path):
    """Distinct keys do NOT need to serialise — both measurements run."""
    a = _write_binary(tmp_path / "a.exe", b"MZaaa")
    b = _write_binary(tmp_path / "b.exe", b"MZbbb")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> None:
        await asyncio.gather(cache.get(a), cache.get(b))

    asyncio.run(_run())
    assert len(provider.calls) == 2
    assert {call[0].name for call in provider.calls} == {"a.exe", "b.exe"}


# ============================================================================
# Filter cache key — filtered and unfiltered live in separate slots
# ============================================================================


def test_filter_rvas_forwarded_to_provider(tmp_path: Path):
    """Filter given to ``get`` reaches the provider unchanged."""
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    flt = frozenset({0x1000, 0x2000})
    baseline = asyncio.run(cache.get(binary, filter_rvas=flt))

    assert baseline.filter_rvas == flt
    assert provider.calls == [(binary, flt)]


def test_filtered_and_unfiltered_live_in_separate_cache_slots(tmp_path: Path):
    """Filtered and unfiltered measurements of the same binary are
    legitimately distinct — the cache does not overwrite one with the
    other."""
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> None:
        await cache.get(binary)  # unfiltered
        await cache.get(binary, filter_rvas=frozenset({0x1000}))
        # Repeats — each hits its own cache slot.
        await cache.get(binary)
        await cache.get(binary, filter_rvas=frozenset({0x1000}))

    asyncio.run(_run())
    assert len(provider.calls) == 2
    assert len(cache) == 2


def test_different_filters_produce_different_cache_entries(tmp_path: Path):
    """Two different filter sets on the same binary = two cache slots."""
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    f1 = frozenset({0x1000})
    f2 = frozenset({0x2000})

    async def _run() -> None:
        await cache.get(binary, filter_rvas=f1)
        await cache.get(binary, filter_rvas=f2)
        await cache.get(binary, filter_rvas=f1)  # cache hit
        await cache.get(binary, filter_rvas=f2)  # cache hit

    asyncio.run(_run())
    assert len(provider.calls) == 2
    filters_observed = {call[1] for call in provider.calls}
    assert filters_observed == {f1, f2}


def test_empty_filter_distinct_from_unfiltered(tmp_path: Path):
    """An empty frozenset is a legitimate "filter matches nothing"
    signal — it must not collapse into the unfiltered slot."""
    binary = _write_binary(tmp_path / "foo.exe")
    provider = _StubProvider()
    cache = CfgBaselineCache(provider)

    async def _run() -> None:
        await cache.get(binary)                           # unfiltered
        await cache.get(binary, filter_rvas=frozenset())  # empty filter

    asyncio.run(_run())
    assert len(provider.calls) == 2
    assert len(cache) == 2
