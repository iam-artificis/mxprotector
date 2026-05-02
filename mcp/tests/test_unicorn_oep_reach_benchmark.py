"""Unit tests for benchmarks.unicorn_oep_reach_benchmark.

Mocks ``ensure_protected``, ``read_entry_point_rva`` and
``run_oep_reach`` at the benchmark module level. Mirrors the test
shape of ``test_budget_to_crack_benchmark`` so the two
"OEP-reach via different backend" tests stay structurally identical.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import unicorn_oep_reach_benchmark as uob
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.emulation.unicorn import (
    OepReachUnicornResult,
    UnicornNotAvailableError,
)
from mx_mcp.emulation.unicorn.runner import (
    TERM_BUDGET_INSTR,
    TERM_REACHED_OEP,
    TERM_UNMAPPED_FETCH,
)


def _make_corpus(tmp_path: Path, entries: list[dict]) -> Corpus:
    corpus_root = tmp_path / "corpus"
    corpus_root.mkdir()
    for spec in entries:
        for key in ("binary", "pre_protected", "pre_sidecar"):
            if key in spec:
                p = corpus_root / spec[key]
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_bytes(b"\x4d\x5a")
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": entries}),
        encoding="utf-8",
    )
    return Corpus.load(corpus_root)


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


def _reached(instr=42) -> OepReachUnicornResult:
    return OepReachUnicornResult(
        reached=True, instructions_executed=instr, wall_ms=10,
        termination_reason=TERM_REACHED_OEP, error=None,
    )


def _unmapped(instr=8) -> OepReachUnicornResult:
    return OepReachUnicornResult(
        reached=False, instructions_executed=instr, wall_ms=2,
        termination_reason=TERM_UNMAPPED_FETCH,
        error="UC_ERR_FETCH_UNMAPPED",
    )


def _budget_hit(instr=200000) -> OepReachUnicornResult:
    return OepReachUnicornResult(
        reached=False, instructions_executed=instr, wall_ms=20,
        termination_reason=TERM_BUDGET_INSTR, error=None,
    )


def _install_mocks(
    monkeypatch,
    *,
    ep_rva_per_entry: dict[str, int],
    run_per_entry: dict[str, OepReachUnicornResult] | None = None,
    run_raises: dict[str, BaseException] | None = None,
    ep_raises: dict[str, BaseException] | None = None,
):
    build_calls: list[str] = []
    run_calls: list[tuple[str, int]] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        out = output_dir / f"{entry.name}.mx.exe"
        out.write_bytes(b"\x4d\x5a")
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or out,
            protected_binary=out, sidecar_path=None,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    def fake_read_ep(binary_path: Path) -> int:
        name = binary_path.stem
        if ep_raises and name in ep_raises:
            raise ep_raises[name]
        return ep_rva_per_entry.get(name, 0x1000)

    def fake_run(binary_path: Path, target_oep_rva: int, budget):
        name = binary_path.stem
        if name.endswith(".mx"):
            name = name[: -len(".mx")]
        run_calls.append((name, target_oep_rva))
        if run_raises and name in run_raises:
            raise run_raises[name]
        if run_per_entry and name in run_per_entry:
            return run_per_entry[name]
        return _unmapped()

    monkeypatch.setattr(uob, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        uob, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "run_calls": run_calls,
        "run_fn": fake_run,
        "read_entry_point_fn": fake_read_ep,
    }


# ============================================================================
# Happy paths
# ============================================================================


def test_unmapped_records_low_instruction_count(tmp_path, monkeypatch):
    """Unicorn trips on PEB / IAT → low instruction count, reached=False.

    This is the *expected* outcome on a strong build. Verifies the
    metric reads as ``defence held``.
    """
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"alpha": 0x4000},
        run_per_entry={"alpha": _unmapped(instr=12)},
    )
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.errors == []
    by_name = {m.name: m for m in result.metrics}

    reached = by_name["unicorn_oep_reached"]
    assert reached.direction is MetricDirection.FALSE_BEST
    assert reached.samples[0].value is False

    instr = by_name["unicorn_instructions_to_oep"]
    assert instr.direction is MetricDirection.LOWER_BETTER
    assert instr.samples[0].value == 12


def test_reached_is_a_defence_break(tmp_path, monkeypatch):
    """Unicorn landed PC at OEP within budget → defence broken."""
    corpus = _make_corpus(tmp_path, [
        {"name": "weak", "binary": "bin/w.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"weak": 0x4000},
        run_per_entry={"weak": _reached(instr=80)},
    )
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["unicorn_oep_reached"].samples[0].value is True
    assert by_name["unicorn_instructions_to_oep"].samples[0].value == 80


def test_mixed_corpus_aggregates_distribution(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["packer", "exe"]},
        {"name": "b", "binary": "bin/b.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"a": 0x4000, "b": 0x4000},
        run_per_entry={
            "a": _unmapped(instr=10),
            "b": _budget_hit(instr=200_000),
        },
    )
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    instr_metric = next(m for m in result.metrics
                        if m.name == "unicorn_instructions_to_oep")
    assert instr_metric.aggregate.n_samples == 2
    assert instr_metric.aggregate.mean == (10 + 200_000) / 2


# ============================================================================
# Fail-closed
# ============================================================================


def test_backend_missing_aborts_loop(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["packer", "exe"]},
        {"name": "b", "binary": "bin/b.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"a": 0x4000, "b": 0x4000},
        run_raises={"a": UnicornNotAvailableError("backend disabled")},
    )
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert mocks["build_calls"] == ["a"]
    assert any("unicorn backend" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_pre_protected_entries_rejected(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(monkeypatch, ep_rva_per_entry={})
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("pre-protected" in e for e in result.errors)
    assert mocks["build_calls"] == []


def test_unprotected_ep_unreadable_emits_per_entry_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "broken", "binary": "bin/broken.exe", "tags": ["packer", "exe"]},
        {"name": "ok", "binary": "bin/ok.exe", "tags": ["packer", "exe"]},
    ])

    from mx_mcp.common.pe_reader import NotAPeError

    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"ok": 0x4000},
        ep_raises={"broken": NotAPeError("bad header")},
        run_per_entry={"ok": _unmapped(instr=15)},
    )
    bench = uob.UnicornOepReachBenchmark(
        run_fn=mocks["run_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("cannot read unprotected EP RVA" in e for e in result.errors)

    instr = next(m for m in result.metrics
                 if m.name == "unicorn_instructions_to_oep")
    assert [s.sample_name for s in instr.samples] == ["ok"]


# ============================================================================
# Metadata
# ============================================================================


def test_category_and_tier_are_fast_packer():
    bench = uob.UnicornOepReachBenchmark()
    assert bench.category == "packer"
    assert bench.tier == "fast"
    assert bench.corpus_tags == frozenset({"packer", "exe"})
