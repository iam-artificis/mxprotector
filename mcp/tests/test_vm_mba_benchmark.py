"""Unit tests for benchmarks.vm_mba_benchmark.

Mocks ``ensure_protected`` + ``extract_handler_expression`` +
simplifier backends. No real angr, no real builder. Covers the
benchmark's orchestration: sampling cap, per-entry / per-backend
error handling, metric-row shape, extractor-missing self-skip.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from mx_mcp.benchmarks import vm_mba_benchmark as vmba
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
from mx_mcp.deobfuscation.mba.expression import MbaExpression
from mx_mcp.deobfuscation.mba.simplifier import (
    BackendUnavailableError,
    IMbaSimplifier,
    SimplificationResult,
)
from mx_mcp.deobfuscation.mba.extractor import ExtractorUnavailableError


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
            dispatcher_rva=0x2000, handler_table_rva=0x3000,
            handlers=[
                VmHandlerLabel(
                    id=i, rva=0x4000 + i * 0x40, size=0x30,
                    opcode=f"op_{i:02d}",
                )
                for i in range(n_handlers)
            ],
        ),
        guard=GuardHints(), strings=StringHints(), iat=IatHints(),
    )


@dataclass
class _FakeAst:
    op: str = "BVV"
    args: tuple = ()
    depth: int = 1


def _fake_expr(nodes: int, rva: int = 0x4000, opcode: str = "op") -> MbaExpression:
    return MbaExpression(
        handler_rva=rva, handler_opcode=opcode,
        ast=_FakeAst(), ast_nodes=nodes, ast_depth=1,
    )


class _FakeSimplifier(IMbaSimplifier):
    """Test simplifier driven by a (rva → result) dispatch table."""

    def __init__(
        self,
        name: str,
        *,
        results_by_rva: dict[int, SimplificationResult] | None = None,
        unavailable_after: int | None = None,
    ) -> None:
        self.name = name
        self._results = results_by_rva or {}
        self._unavailable_after = unavailable_after
        self._call_count = 0

    def simplify(self, expr: MbaExpression) -> SimplificationResult:
        self._call_count += 1
        if self._unavailable_after is not None \
           and self._call_count > self._unavailable_after:
            raise BackendUnavailableError(f"{self.name} fake unavailable")
        if expr.handler_rva in self._results:
            return self._results[expr.handler_rva]
        # Default: "not simplified" — nodes unchanged.
        return SimplificationResult(
            backend=self.name, simplified=False,
            nodes_before=expr.ast_nodes, nodes_after=expr.ast_nodes,
            wall_ms=1,
        )


def _install_mocks(
    monkeypatch,
    *,
    sidecar_handlers: dict[str, int],
    expr_nodes_by_rva: dict[int, int] | None = None,
    extract_raises_entry: dict[str, BaseException] | None = None,
    extract_raises_rva: dict[int, BaseException] | None = None,
):
    """Patch ensure_protected + extractor seam + builder path."""
    build_calls: list[str] = []
    extract_calls: list[tuple[str, int]] = []

    sidecars: dict[str, Sidecar] = {
        name: _make_sidecar(n) for name, n in sidecar_handlers.items()
    }

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        output = output_dir / f"{entry.name}.mx.exe"
        output.write_bytes(b"\x4d\x5a")
        sidecar_path = output.parent / f"{output.name}.mxtrace.json"
        sidecar_path.write_text(
            sidecars[entry.name].model_dump_json(), encoding="utf-8",
        )
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or output,
            protected_binary=output, sidecar_path=sidecar_path,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    def fake_extract(binary_path, rva, size, opcode="", *, budget=None):
        # Derive entry name from binary filename.
        entry_name = Path(binary_path).stem
        if entry_name.endswith(".mx"):
            entry_name = entry_name[: -len(".mx")]
        extract_calls.append((entry_name, rva))
        if extract_raises_entry and entry_name in extract_raises_entry:
            raise extract_raises_entry[entry_name]
        if extract_raises_rva and rva in extract_raises_rva:
            raise extract_raises_rva[rva]
        nodes = (expr_nodes_by_rva or {}).get(rva, 10)
        return _fake_expr(nodes, rva, opcode)

    monkeypatch.setattr(vmba, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        vmba, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "extract_calls": extract_calls,
        "extract_fn": fake_extract,
    }


# ============================================================================
# Happy path
# ============================================================================


def test_records_ast_mean_and_rate(tmp_path: Path, monkeypatch):
    """4 handlers with varying AST sizes → mean recorded; 2 of 4
    simplified → rate=0.5."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(4)]
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 4},
        expr_nodes_by_rva={rvas[0]: 10, rvas[1]: 20, rvas[2]: 30, rvas[3]: 40},
    )
    simp = _FakeSimplifier("fake", results_by_rva={
        rvas[0]: SimplificationResult(
            backend="fake", simplified=True, nodes_before=10,
            nodes_after=3, wall_ms=1),
        rvas[1]: SimplificationResult(
            backend="fake", simplified=True, nodes_before=20,
            nodes_after=5, wall_ms=1),
        rvas[2]: SimplificationResult(
            backend="fake", simplified=False, nodes_before=30,
            nodes_after=30, wall_ms=1),
        rvas[3]: SimplificationResult(
            backend="fake", simplified=False, nodes_before=40,
            nodes_after=40, wall_ms=1),
    })
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"], simplifiers=[simp],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.errors == []
    by_name = {m.name: m for m in result.metrics}
    ast_metric = by_name["vm_mba_expression_mean_ast_nodes"]
    rate_metric = by_name["vm_mba_fake_simplification_rate"]
    # Mean of 10+20+30+40 = 25.
    assert ast_metric.samples[0].value == 25.0
    assert ast_metric.direction is MetricDirection.HIGHER_BETTER
    # 2 of 4 simplified → rate = 0.5.
    assert rate_metric.samples[0].value == 0.5
    assert rate_metric.direction is MetricDirection.LOWER_BETTER


def test_handler_sampling_cap_respected(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "big", "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={"big": 50})
    simp = _FakeSimplifier("fake")
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"], simplifiers=[simp],
        max_handlers_per_entry=8,
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["extract_calls"]) == 8
    ev = result.metrics[0].samples[0].evidence
    assert ev["handler_total"] == 50
    assert ev["handlers_sampled"] == 8
    assert ev["handlers_truncated"] is True


def test_multiple_simplifiers_each_get_metric_row(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"alpha": 3},
    )
    simp_a = _FakeSimplifier("alpha")
    simp_b = _FakeSimplifier("beta")
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"], simplifiers=[simp_a, simp_b],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    names = {m.name for m in result.metrics}
    assert "vm_mba_expression_mean_ast_nodes" in names
    assert "vm_mba_alpha_simplification_rate" in names
    assert "vm_mba_beta_simplification_rate" in names


# ============================================================================
# Per-backend fail-closed
# ============================================================================


def test_unavailable_backend_dropped_with_error_note(tmp_path: Path, monkeypatch):
    """A simplifier that raises BackendUnavailableError is dropped
    for the rest of the run; a single entry-level error note is
    emitted; other simplifiers keep working."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "beta",  "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 3, "beta": 3},
    )
    # Dead backend fails on first call; healthy one keeps going.
    dead = _FakeSimplifier("dead", unavailable_after=0)
    healthy = _FakeSimplifier("healthy")
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"], simplifiers=[dead, healthy],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    # One error mentions the dead backend.
    assert any("'dead' unavailable" in e for e in result.errors)
    by_name = {m.name: m for m in result.metrics}
    # Healthy backend has samples for both entries.
    healthy_samples = by_name["vm_mba_healthy_simplification_rate"].samples
    assert {s.sample_name for s in healthy_samples} == {"alpha", "beta"}
    # Dead backend has no per-entry rate sample (or a None-valued one).
    dead_samples = by_name["vm_mba_dead_simplification_rate"].samples
    for s in dead_samples:
        assert s.value is None


def test_extractor_unavailable_stops_loop(tmp_path: Path, monkeypatch):
    """ExtractorUnavailableError on the first entry breaks the loop
    and surfaces a single benchmark error."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "beta",  "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 1, "beta": 1},
        extract_raises_entry={
            "alpha": ExtractorUnavailableError("fake no angr"),
        },
    )
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"],
        simplifiers=[_FakeSimplifier("fake")],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    # Loop breaks after alpha's extractor failure.
    assert mocks["build_calls"] == ["alpha"]
    assert any("extractor unavailable" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_per_handler_extractor_error_excluded_from_samples(
    tmp_path: Path, monkeypatch,
):
    """A handler whose extract_fn raises is excluded from the mean
    and its backend-per-handler slot. Other handlers on the entry
    still contribute."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(3)]
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 3},
        expr_nodes_by_rva={rvas[0]: 10, rvas[2]: 30},
        extract_raises_rva={rvas[1]: RuntimeError("extract blow-up")},
    )
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"],
        simplifiers=[_FakeSimplifier("fake")],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    ast = by_name["vm_mba_expression_mean_ast_nodes"].samples[0]
    # Mean of two healthy handlers: (10+30)/2 = 20.
    assert ast.value == 20.0
    assert ast.evidence["extractor_errors"] == 1


def test_all_handlers_errored_emits_none_sample(tmp_path: Path, monkeypatch):
    """Every handler's extractor failed → AST mean sample is None
    and the rate-sample is not emitted (returns early)."""
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(2)]
    mocks = _install_mocks(
        monkeypatch,
        sidecar_handlers={"alpha": 2},
        extract_raises_rva={rvas[0]: RuntimeError("x"),
                             rvas[1]: RuntimeError("y")},
    )
    bench = vmba.VmMbaBenchmark(
        extract_fn=mocks["extract_fn"],
        simplifiers=[_FakeSimplifier("fake")],
    )
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    ast_samples = by_name["vm_mba_expression_mean_ast_nodes"].samples
    assert len(ast_samples) == 1
    assert ast_samples[0].value is None
    # No rate sample because _record_samples returns early.
    rate_samples = by_name["vm_mba_fake_simplification_rate"].samples
    assert rate_samples == []


# ============================================================================
# Entry-level gating
# ============================================================================


def test_pre_protected_entries_rejected(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={})
    bench = vmba.VmMbaBenchmark(extract_fn=mocks["extract_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("pre-protected" in e for e in result.errors)
    assert mocks["build_calls"] == []


def test_empty_sidecar_handlers_emits_per_entry_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "novm", "binary": "bin/n.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={"novm": 0})
    bench = vmba.VmMbaBenchmark(extract_fn=mocks["extract_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no VM handlers" in e for e in result.errors)


def test_non_vm_entries_skipped(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "cff_only", "binary": "bin/c.exe", "tags": ["cff"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={})
    bench = vmba.VmMbaBenchmark(extract_fn=mocks["extract_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert mocks["build_calls"] == []
    assert any("no corpus entries tagged 'vm'" in e for e in result.errors)


def test_category_and_tier_are_slow_vm():
    bench = vmba.VmMbaBenchmark()
    assert bench.category == "vm"
    assert bench.tier == "slow"
    assert "vm" in bench.corpus_tags


def test_default_simplifier_list_includes_claripy_and_pattern():
    """The default ensemble must contain both always-on backends.

    Pinning this ordering protects the metric-row contract: callers
    that diff baselines across runs assume the registered backends
    do not silently change. Any reorder is a deliberate, reviewable
    edit to this assertion.
    """
    bench = vmba.VmMbaBenchmark()
    backend_names = [s.name for s in bench._simplifiers]
    assert backend_names == ["claripy", "pattern"]
