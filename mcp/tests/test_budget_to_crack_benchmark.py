"""Unit tests for benchmarks.budget_to_crack_benchmark.

Mocks both ``ensure_protected`` (no real builder), ``read_entry_point_rva``
(no real PE parsing) and ``analyse_oep_reach`` (no real angr) at the
benchmark module level. The benchmark wraps a single function call per
entry, so most assertions look at metric values + per-entry evidence.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import budget_to_crack_benchmark as btc
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.symbolic.angr.oep_reach import (
    AngrNotAvailableError,
    OepReachResult,
    TERM_BUDGET_STEPS,
    TERM_REACHED,
)


# ============================================================================
# Fixture factories
# ============================================================================


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


def _reached(steps: int) -> OepReachResult:
    return OepReachResult(
        reached=True, steps=steps, paths_explored=1, wall_ms=10,
        termination_reason=TERM_REACHED, error=None,
    )


def _budget_hit(steps: int) -> OepReachResult:
    return OepReachResult(
        reached=False, steps=steps, paths_explored=1, wall_ms=10,
        termination_reason=TERM_BUDGET_STEPS, error=None,
    )


def _install_mocks(
    monkeypatch,
    *,
    ep_rva_per_entry: dict[str, int],
    analyse_per_entry: dict[str, OepReachResult] | None = None,
    analyse_raises: dict[str, BaseException] | None = None,
    ep_raises: dict[str, BaseException] | None = None,
):
    build_calls: list[str] = []
    analyse_calls: list[tuple[str, int]] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a" + b"\x00" * 64)
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output,
            sidecar_path=None,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    def fake_read_ep(binary_path: Path) -> int:
        # Recover the entry name from the binary's filename: tests pass
        # in the unprotected source, so the name is "<entry>.exe".
        entry_name = binary_path.stem
        if ep_raises and entry_name in ep_raises:
            raise ep_raises[entry_name]
        if entry_name in ep_rva_per_entry:
            return ep_rva_per_entry[entry_name]
        # Fallback for unmapped entries — keeps tests focused on what
        # they explicitly script.
        return 0x1000

    def fake_analyse(binary_path: Path, target_oep_rva: int, budget):
        # The protected binary is named "<entry>.mx.exe" — strip the
        # suffix so the test can key per entry name.
        entry_name = binary_path.stem
        if entry_name.endswith(".mx"):
            entry_name = entry_name[: -len(".mx")]
        analyse_calls.append((entry_name, target_oep_rva))
        if analyse_raises and entry_name in analyse_raises:
            raise analyse_raises[entry_name]
        if analyse_per_entry and entry_name in analyse_per_entry:
            return analyse_per_entry[entry_name]
        return _reached(steps=10)

    monkeypatch.setattr(btc, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        btc, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "analyse_calls": analyse_calls,
        "analyse_fn": fake_analyse,
        "read_entry_point_fn": fake_read_ep,
    }


# ============================================================================
# Happy path — reached & budget-hit produce the right two metrics
# ============================================================================


def test_reached_within_budget_records_step_count(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/alpha.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"alpha": 0x4000},
        analyse_per_entry={"alpha": _reached(steps=42)},
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.errors == []
    assert mocks["analyse_calls"] == [("alpha", 0x4000)]

    by_name = {m.name: m for m in result.metrics}

    # Step-count metric: HIGHER_BETTER, value = 42.
    steps_metric = by_name["budget_to_crack_steps_to_oep"]
    assert steps_metric.direction is MetricDirection.HIGHER_BETTER
    assert steps_metric.samples[0].value == 42
    assert steps_metric.samples[0].evidence["target_oep_rva"] == 0x4000
    assert steps_metric.samples[0].evidence["termination_reason"] == TERM_REACHED

    # Reached metric: FALSE_BEST, True (defence broken).
    reached_metric = by_name["budget_to_crack_oep_reached"]
    assert reached_metric.direction is MetricDirection.FALSE_BEST
    assert reached_metric.samples[0].value is True


def test_budget_exhausted_records_cap_and_false(tmp_path, monkeypatch):
    """Resistant build: angr ran out of budget without reaching OEP.

    HIGHER_BETTER metric pins at the cap; FALSE_BEST metric stays
    False. This is the "score=1.0" reading on the visualisation.
    """
    corpus = _make_corpus(tmp_path, [
        {"name": "fortress", "binary": "bin/fortress.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"fortress": 0x4000},
        analyse_per_entry={"fortress": _budget_hit(steps=2000)},
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["budget_to_crack_steps_to_oep"].samples[0].value == 2000
    assert by_name["budget_to_crack_oep_reached"].samples[0].value is False
    ev = by_name["budget_to_crack_steps_to_oep"].samples[0].evidence
    assert ev["termination_reason"] == TERM_BUDGET_STEPS


def test_mixed_corpus_aggregates_distribution(tmp_path, monkeypatch):
    """Mixed corpus: one weak (reached fast), one strong (budget hit).

    Verifies that the per-corpus aggregate (p10/p50/p90) is computed
    over both samples — the corpus-based gate model in MCP.md leans
    on these percentiles.
    """
    corpus = _make_corpus(tmp_path, [
        {"name": "weak", "binary": "bin/w.exe", "tags": ["packer", "exe"]},
        {"name": "strong", "binary": "bin/s.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"weak": 0x4000, "strong": 0x4000},
        analyse_per_entry={
            "weak": _reached(steps=20),
            "strong": _budget_hit(steps=2000),
        },
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    steps = by_name["budget_to_crack_steps_to_oep"]
    assert {s.sample_name for s in steps.samples} == {"weak", "strong"}
    assert steps.aggregate.n_samples == 2
    assert steps.aggregate.n_errors == 0
    # Mean of 20 and 2000 is 1010.
    assert steps.aggregate.mean == 1010.0


# ============================================================================
# Fail-closed paths
# ============================================================================


def test_backend_missing_aborts_loop(tmp_path, monkeypatch):
    """One AngrNotAvailableError stops the loop — no further builds.

    Mirrors vm_symbolic_benchmark's contract so the two slow-tier
    angr benchmarks behave identically when angr is missing.
    """
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["packer", "exe"]},
        {"name": "beta",  "binary": "bin/b.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"alpha": 0x4000, "beta": 0x4000},
        analyse_raises={"alpha": AngrNotAvailableError("backend disabled")},
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert mocks["build_calls"] == ["alpha"]
    assert any("angr backend" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_pre_protected_entries_rejected(tmp_path, monkeypatch):
    """No unprotected source → no ground-truth OEP RVA → reject."""
    corpus = _make_corpus(tmp_path, [
        {
            "name": "legacy", "pre_protected": "legacy/old.exe",
            "tags": ["packer", "exe"],
        },
    ])
    mocks = _install_mocks(monkeypatch, ep_rva_per_entry={})
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("pre-protected" in e for e in result.errors)
    assert mocks["build_calls"] == []
    assert mocks["analyse_calls"] == []


def test_unprotected_ep_unreadable_emits_per_entry_error(tmp_path, monkeypatch):
    """Header parse failure on the unprotected PE → per-entry error.

    No sample is recorded for this entry (no ground truth) but the
    benchmark continues with the remaining entries.
    """
    corpus = _make_corpus(tmp_path, [
        {"name": "broken", "binary": "bin/broken.exe", "tags": ["packer", "exe"]},
        {"name": "ok",     "binary": "bin/ok.exe",     "tags": ["packer", "exe"]},
    ])

    from mx_mcp.common.pe_reader import NotAPeError

    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"ok": 0x4000},
        ep_raises={"broken": NotAPeError("DOS magic missing")},
        analyse_per_entry={"ok": _reached(steps=15)},
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("cannot read unprotected EP RVA" in e for e in result.errors)
    # ok still produced a sample.
    by_name = {m.name: m for m in result.metrics}
    samples = by_name["budget_to_crack_steps_to_oep"].samples
    assert [s.sample_name for s in samples] == ["ok"]
    assert samples[0].value == 15


def test_analyse_raises_general_exception_records_per_entry_error(
    tmp_path, monkeypatch,
):
    """An unexpected exception from the runner → per-entry error,
    next entry continues."""
    corpus = _make_corpus(tmp_path, [
        {"name": "ouch", "binary": "bin/ouch.exe", "tags": ["packer", "exe"]},
        {"name": "fine", "binary": "bin/fine.exe", "tags": ["packer", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        ep_rva_per_entry={"ouch": 0x4000, "fine": 0x4000},
        analyse_raises={"ouch": RuntimeError("solver wedged")},
        analyse_per_entry={"fine": _reached(steps=33)},
    )
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("RuntimeError: solver wedged" in e for e in result.errors)
    by_name = {m.name: m for m in result.metrics}
    samples = by_name["budget_to_crack_steps_to_oep"].samples
    assert [s.sample_name for s in samples] == ["fine"]
    assert samples[0].value == 33


# ============================================================================
# Filtering / metadata
# ============================================================================


def test_non_packer_entries_skipped(tmp_path, monkeypatch):
    """Entries lacking ``packer`` tag drop out — measure_defense routes
    them through other benchmarks instead."""
    corpus = _make_corpus(tmp_path, [
        {"name": "vmonly", "binary": "bin/v.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, ep_rva_per_entry={})
    bench = btc.BudgetToCrackBenchmark(
        analyse_fn=mocks["analyse_fn"],
        read_entry_point_fn=mocks["read_entry_point_fn"],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert mocks["build_calls"] == []
    assert any("no corpus entries tagged" in e for e in result.errors)


def test_category_and_tier_are_slow_budget_to_crack():
    bench = btc.BudgetToCrackBenchmark()
    assert bench.category == "budget_to_crack"
    assert bench.tier == "slow"
    assert bench.corpus_tags == frozenset({"packer", "exe"})
