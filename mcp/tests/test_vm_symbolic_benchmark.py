"""Unit tests for benchmarks.vm_symbolic_benchmark.

Mocks both ``ensure_protected`` (no real builder) and ``analyse_handler``
(no real angr) at the benchmark module level. Each mocked
``analyse_handler`` is keyed by ``(entry_name, handler_rva)`` so a test
can inject per-handler outcomes to verify rate / cost arithmetic.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import vm_symbolic_benchmark as vsb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.common.sidecar import (
    BuildInfo,
    CffHints,
    GuardHints,
    IatHints,
    Sidecar,
    StringHints,
    VmHandlerLabel,
    VmHints,
)
from mx_mcp.symbolic.angr.runner import (
    AngrNotAvailableError,
    HandlerAnalysisResult,
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


def _make_sidecar(n_handlers: int) -> Sidecar:
    return Sidecar(
        schema_version=1,
        build=BuildInfo(input="i", output="o", level="strong", timestamp="t"),
        sections={},
        cff=CffHints(),
        vm=VmHints(
            dispatcher_rva=0x2000,
            handler_table_rva=0x3000,
            handlers=[
                VmHandlerLabel(
                    id=i, rva=0x4000 + i * 0x40, size=0x30,
                    opcode=f"op_{i:02d}",
                )
                for i in range(n_handlers)
            ],
        ),
        guard=GuardHints(),
        strings=StringHints(),
        iat=IatHints(),
    )


def _ok_result(*, summarised=True, steps=100, reason=None):
    return HandlerAnalysisResult(
        summarised=summarised,
        steps=steps,
        paths_explored=1,
        wall_ms=5,
        termination_reason=(
            reason if reason is not None
            else ("cleanly_finished" if summarised else "budget_steps")
        ),
        error=None,
    )


def _err_result(phase="step_raised"):
    return HandlerAnalysisResult(
        summarised=False, steps=2, paths_explored=1, wall_ms=1,
        termination_reason="errored",
        error=f"{phase}: RuntimeError: fake",
    )


def _install_mocks(
    monkeypatch,
    *,
    sidecar_handlers: dict[str, int],
    analyse_map: dict[tuple[str, int], HandlerAnalysisResult] | None = None,
    analyse_raises: dict[str, BaseException] | None = None,
):
    """Patch ensure_protected + analyse seam + builder path + sidecar load.

    - ``sidecar_handlers``: entry name → number of handlers in the
      synthetic sidecar produced for that entry.
    - ``analyse_map``: per-(entry, rva) mock outcome; defaults to
      ``_ok_result()`` (clean summarisation in 100 steps) for unmapped
      handlers.
    - ``analyse_raises``: per-entry exception raised by the mocked
      analyse_fn before the batch runs. Used to exercise the backend-
      missing path.
    """
    build_calls: list[str] = []
    analyse_calls: list[tuple[str, int]] = []
    sidecars: dict[str, Sidecar] = {
        name: _make_sidecar(n) for name, n in sidecar_handlers.items()
    }

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a" + b"\x00" * 64)
        sidecar_path = output.parent / f"{output.name}.mxtrace.json"
        sidecar_path.write_text(
            sidecars[entry.name].model_dump_json(), encoding="utf-8",
        )
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output,
            sidecar_path=sidecar_path,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    def fake_analyse(binary_path, handler_rva, handler_size, budget):
        # Recover the entry name from the binary filename.
        entry_name = Path(binary_path).stem
        # strip trailing ".mx" from e.g. "alpha.mx.exe" → stem is "alpha.mx"
        if entry_name.endswith(".mx"):
            entry_name = entry_name[: -len(".mx")]
        analyse_calls.append((entry_name, handler_rva))
        if analyse_raises and entry_name in analyse_raises:
            raise analyse_raises[entry_name]
        if analyse_map and (entry_name, handler_rva) in analyse_map:
            return analyse_map[(entry_name, handler_rva)]
        return _ok_result()

    monkeypatch.setattr(vsb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        vsb, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "analyse_calls": analyse_calls,
        "analyse_fn": fake_analyse,
    }


# ============================================================================
# Happy path — rate + cost arithmetic
# ============================================================================


def test_clean_summarisation_produces_rate_one(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm", "exe"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 4},
        analyse_map={
            ("alpha", 0x4000 + i * 0x40): _ok_result(steps=100)
            for i in range(4)
        },
    )
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.errors == []
    by_name = {m.name: m for m in result.metrics}
    # All 4 handlers summarised → rate = 1.0.
    assert by_name["vm_handler_summarization_rate"].samples[0].value == 1.0
    assert by_name["vm_symbolic_cost_mean_steps"].samples[0].value == 100.0
    assert by_name["vm_handler_summarization_rate"].direction \
        is MetricDirection.LOWER_BETTER
    assert by_name["vm_symbolic_cost_mean_steps"].direction \
        is MetricDirection.HIGHER_BETTER


def test_mixed_outcomes_compute_correct_rate_and_mean(tmp_path, monkeypatch):
    """2 of 4 handlers summarise at 50 steps; the other 2 exhaust the
    500-step cap. Rate = 0.5, mean_steps = (50+50+500+500)/4 = 275."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(4)]
    analyse_map = {
        ("alpha", rvas[0]): _ok_result(summarised=True, steps=50),
        ("alpha", rvas[1]): _ok_result(summarised=True, steps=50),
        ("alpha", rvas[2]): _ok_result(summarised=False, steps=500,
                                       reason="budget_steps"),
        ("alpha", rvas[3]): _ok_result(summarised=False, steps=500,
                                       reason="budget_steps"),
    }
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"alpha": 4}, analyse_map=analyse_map,
    )
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_handler_summarization_rate"].samples[0].value == 0.5
    assert by_name["vm_symbolic_cost_mean_steps"].samples[0].value == 275.0


def test_errored_handler_counts_as_summarised_in_rate(tmp_path, monkeypatch):
    """Fail-closed: a backend-side angr error does NOT let the defence
    score inflate — the errored handler is added to the numerator of
    the summarisation rate so the metric never looks artificially low
    due to a measurement glitch."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(3)]
    analyse_map = {
        ("alpha", rvas[0]): _ok_result(summarised=True, steps=30),
        ("alpha", rvas[1]): _err_result(),
        ("alpha", rvas[2]): _ok_result(summarised=False, steps=500,
                                       reason="budget_steps"),
    }
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"alpha": 3}, analyse_map=analyse_map,
    )
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    # (summarised=1 + errored=1) / total=3 = 0.666...
    rate = by_name["vm_handler_summarization_rate"].samples[0].value
    assert abs(rate - (2.0 / 3.0)) < 1e-9
    ev = by_name["vm_handler_summarization_rate"].samples[0].evidence
    assert ev["summarised"] == 1
    assert ev["summarised_effective"] == 2
    assert ev["errored"] == 1


# ============================================================================
# max_handlers_per_entry sampling cap
# ============================================================================


def test_handler_sampling_cap_is_respected(tmp_path, monkeypatch):
    """A sidecar with 50 handlers but a cap of 10 → only 10 analysed."""
    corpus = _make_corpus(tmp_path, [
        {"name": "big", "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={"big": 50})
    bench = vsb.VmSymbolicBenchmark(
        analyse_fn=mocks["analyse_fn"], max_handlers_per_entry=10,
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["analyse_calls"]) == 10
    # First-N deterministic slice: RVAs match the first 10 sidecar entries.
    assert [rva for _, rva in mocks["analyse_calls"]] == [
        0x4000 + i * 0x40 for i in range(10)
    ]

    by_name = {m.name: m for m in result.metrics}
    ev = by_name["vm_handler_summarization_rate"].samples[0].evidence
    assert ev["handler_total"] == 50
    assert ev["handlers_sampled"] == 10
    assert ev["handlers_truncated"] is True


# ============================================================================
# Fail-closed paths
# ============================================================================


def test_backend_missing_surfaces_benchmark_error(tmp_path, monkeypatch):
    """AngrNotAvailableError raised on the first entry stops the loop —
    no further builds — and emits a single benchmark-level error."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "beta", "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 2, "beta": 2},
        analyse_raises={"alpha": AngrNotAvailableError("backend disabled")},
    )
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    # Only alpha built — loop breaks on backend-missing.
    assert mocks["build_calls"] == ["alpha"]
    # At least one error mentions the missing backend.
    assert any("angr backend" in e for e in result.errors)
    # No samples emitted.
    for m in result.metrics:
        assert m.samples == []


def test_empty_sidecar_handlers_emits_per_entry_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "no_vm", "binary": "bin/n.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"no_vm": 0},
    )
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no VM handlers" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_pre_protected_entries_rejected(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={})
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("pre-protected" in e for e in result.errors)
    # ensure_protected is NOT called for pre-protected rejects.
    assert mocks["build_calls"] == []


# ============================================================================
# Filtering / category / tier
# ============================================================================


def test_non_vm_entries_skipped(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "cff_only", "binary": "bin/c.exe", "tags": ["cff"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={})
    bench = vsb.VmSymbolicBenchmark(analyse_fn=mocks["analyse_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert mocks["build_calls"] == []
    assert any("no corpus entries tagged 'vm'" in e for e in result.errors)


def test_category_and_tier_are_slow_vm():
    bench = vsb.VmSymbolicBenchmark()
    assert bench.category == "vm"
    assert bench.tier == "slow"
    assert "vm" in bench.corpus_tags
