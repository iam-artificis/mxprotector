"""Unit tests for benchmarks.vm_benchmark.

Mocks the three backend dependencies:

* ``ensure_protected`` — builds a protected artefact with sidecar.
* ``read_section_bytes`` — returns synthetic VM bytecode.
* baseline cache — injected via constructor; a stub provider yields
  a configured ``CfgBaseline`` (of which only ``text_section_size``
  is consumed by this benchmark).

Tests mirror ``test_cff_benchmark`` structurally so the two benchmark
test suites read the same: same corpus helper, same sidecar helper
shape, same mock-injection pattern.
"""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import vm_benchmark as vb
from mx_mcp.common.baseline import (
    BaselineError,
    CfgBaseline,
    CfgBaselineCache,
)
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.common.pe_reader import NotAPeError, SectionNotFoundError


# ============================================================================
# Corpus + session helpers
# ============================================================================


def _make_corpus(tmp_path: Path, entries: list[tuple[str, list[str]]]) -> Corpus:
    corpus_root = tmp_path / "corpus"
    bin_dir = corpus_root / "bin"
    bin_dir.mkdir(parents=True)
    manifest_entries = []
    for name, tags in entries:
        (bin_dir / f"{name}.exe").write_bytes(b"\x4d\x5a")
        manifest_entries.append({
            "name": name,
            "binary": f"bin/{name}.exe",
            "tags": tags,
        })
    (corpus_root / "corpus.json").write_text(
        json.dumps({"schema_version": 1, "entries": manifest_entries}),
        encoding="utf-8",
    )
    return Corpus.load(corpus_root)


def _fake_session(workspace_root: Path) -> SimpleNamespace:
    return SimpleNamespace(workspace_root=workspace_root)


# ============================================================================
# Baseline stub
# ============================================================================


# Default baseline ``.text`` size. 8 KiB is in the ballpark of small
# unprotected seed binaries — pairing with the default 2 KiB VM
# section gives a density of 0.25 (2048 / 8192), i.e. "bytecode is a
# quarter of the original code footprint".
_DEFAULT_BASELINE_TEXT = 8192


class _StubBaselineProvider:
    """Returns the configured :class:`CfgBaseline` per binary.

    ``overrides`` keys by the unprotected binary's stem. The VM
    benchmark only reads ``text_section_size``; the other CfgBaseline
    fields are filled with dummy values so the object is valid.
    """

    def __init__(
        self,
        *,
        text_size: int = _DEFAULT_BASELINE_TEXT,
        fn_bytes: int = 2048,
        overrides: dict[str, CfgBaseline | Exception] | None = None,
    ) -> None:
        self.calls: list[tuple[Path, frozenset[int] | None]] = []
        self._text_size = text_size
        self._fn_bytes = fn_bytes
        self._overrides = overrides or {}

    async def measure(
        self,
        binary: Path,
        *,
        filter_rvas: frozenset[int] | None = None,
    ) -> CfgBaseline:
        self.calls.append((binary, filter_rvas))
        override = self._overrides.get(binary.stem)
        if isinstance(override, Exception):
            raise override
        if isinstance(override, CfgBaseline):
            return override
        return CfgBaseline(
            binary_path=binary,
            function_count=10,
            total_blocks=100,
            total_cyclomatic=50,
            total_gotos=5,
            functions_total_bytes=self._fn_bytes,
            text_section_size=self._text_size,
            filter_rvas=filter_rvas,
        )


def _build_stub_cache(
    **kwargs,
) -> tuple[CfgBaselineCache, _StubBaselineProvider]:
    provider = _StubBaselineProvider(**kwargs)
    return CfgBaselineCache(provider), provider


# ============================================================================
# Sidecar + build mocks
# ============================================================================


_DEFAULT_VM_RVA = 0x30000
_DEFAULT_VM_SIZE = 0x800
_DEFAULT_HANDLER_COUNT = 3

_DEFAULT_VM_PROTECTED_RVAS: tuple[int, ...] = (0x1500, 0x1800)


def _write_synthetic_sidecar(
    sidecar_path: Path,
    *,
    vm_rva: int = _DEFAULT_VM_RVA,
    vm_size: int = _DEFAULT_VM_SIZE,
    handler_count: int = _DEFAULT_HANDLER_COUNT,
    include_vm: bool = True,
    protected_rvas: tuple[int, ...] | list[int] | None = None,
) -> None:
    sections: dict = {}
    handlers: list[dict] = []
    if include_vm:
        sections["vm"] = {
            "name": ".ve3mx9",
            "rva": vm_rva,
            "size": vm_size,
            "characteristics": 0x60000020,
        }
        for i in range(handler_count):
            handlers.append({
                "id": i,
                "rva": vm_rva + i * 0x100,
                "size": 0x100,
                "opcode": f"region_{i}",
            })

    if protected_rvas is None:
        protected_rvas = _DEFAULT_VM_PROTECTED_RVAS
    protected_entries = [
        {"rva": int(r), "size": 256, "kind": "vm"}
        for r in protected_rvas
    ]

    payload = {
        "schema_version": 1,
        "build": {
            "input": "in", "output": "out", "level": "strong",
            "timestamp": "2026-04-20T00:00:00Z",
        },
        "sections": sections,
        "cff": {"dispatcher_rva": 0, "state_var_rva": 0,
                "states": [], "predicates": []},
        "vm":  {"dispatcher_rva": vm_rva if include_vm else 0,
                "handler_table_rva": 0,
                "handlers": handlers},
        "guard":   {"regions": []},
        "strings": {"slots": []},
        "iat":     {"rva": 0, "size": 0},
        "protected_functions": protected_entries,
    }
    sidecar_path.write_text(json.dumps(payload), encoding="utf-8")


def _install_mocks(
    monkeypatch,
    *,
    build_map: dict[str, ProtectedBuild | Exception] | None = None,
    bytes_map: dict[str, bytes | Exception] | None = None,
    sidecar_vm_rva: int = _DEFAULT_VM_RVA,
    sidecar_vm_size: int = _DEFAULT_VM_SIZE,
    sidecar_handler_count: int = _DEFAULT_HANDLER_COUNT,
    sidecar_has_vm: bool = True,
    sidecar_omit: bool = False,
    sidecar_protected_rvas: tuple[int, ...] | list[int] | None = None,
) -> dict:
    build_calls: list[Path] = []
    byte_calls: list[tuple[Path, int, int]] = []

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        output = output_dir / f"{entry.name}.mx.exe"
        source_binary = entry.unprotected_binary or entry.pre_protected_binary
        build_calls.append(source_binary)

        behaviour = (build_map or {}).get(entry.name)
        if isinstance(behaviour, Exception):
            raise behaviour

        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(b"\x4d\x5a")

        if behaviour is not None:
            return behaviour

        sidecar_path: Path | None = None
        if not sidecar_omit:
            sidecar_path = output.parent / f"{output.name}.mxtrace.json"
            _write_synthetic_sidecar(
                sidecar_path,
                vm_rva=sidecar_vm_rva,
                vm_size=sidecar_vm_size,
                handler_count=sidecar_handler_count,
                include_vm=sidecar_has_vm,
                protected_rvas=sidecar_protected_rvas,
            )
        return ProtectedBuild(
            unprotected_binary=source_binary,
            protected_binary=output,
            sidecar_path=sidecar_path,
            duration_ms=1,
            stdout_tail="", stderr_tail="",
        )

    def fake_read_section_bytes(binary_path: Path, rva: int, size: int) -> bytes:
        byte_calls.append((binary_path, rva, size))
        key = binary_path.stem.removesuffix(".mx")
        behaviour = (bytes_map or {}).get(key)
        if isinstance(behaviour, Exception):
            raise behaviour
        if isinstance(behaviour, (bytes, bytearray)):
            return bytes(behaviour)
        return bytes((i * 131 + 7) & 0xFF for i in range(size))

    monkeypatch.setattr(vb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(vb, "read_section_bytes", fake_read_section_bytes)
    monkeypatch.setattr(vb, "resolve_builder_path",
                        lambda root: root / "fake_builder.exe")

    return {"build_calls": build_calls, "byte_calls": byte_calls}


# ============================================================================
# Happy-path shape
# ============================================================================


def test_happy_path_emits_one_sample_per_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"]), ("beta", ["vm"])])
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)

    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "vm_static"
    assert result.category == "vm"
    assert result.tier == "fast"
    assert result.errors == []

    assert len(result.metrics) == 4
    metric_names = {m.name for m in result.metrics}
    assert metric_names == {
        "vm_footprint_density",
        "vm_bytecode_entropy",
        "vm_bytecode_bigram_entropy",
        "vm_coverage",
    }
    for m in result.metrics:
        assert m.direction is MetricDirection.HIGHER_BETTER
        assert len(m.samples) == 2

    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"alpha", "beta"}


def test_footprint_equals_vm_section_over_baseline_filtered_fn_bytes(
    tmp_path, monkeypatch,
):
    """Footprint = .vm section bytes / baseline_filtered.functions_total_bytes.

    Numerator is the WHOLE .vm section (bytecode + dispatcher +
    handlers — not separable today). This is honest per the module
    docstring — the metric measures VM footprint, not pure bytecode
    expansion."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": b"\xAB" * 2048},
        sidecar_vm_size=2048,
    )
    # fn_bytes = sum of sizes of protected functions (the filtered
    # baseline's denominator). 512 B of source → 2048 B .vm = 4.0x
    # footprint.
    cache, _ = _build_stub_cache(fn_bytes=512)
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_footprint_density"].samples[0].value == 4.0


def test_coverage_equals_filtered_bytes_over_total_text(tmp_path, monkeypatch):
    """Coverage = baseline_filtered.functions_total_bytes /
    baseline_total.text_section_size. Stub returns both values from
    the SAME object (it doesn't discriminate by filter), so coverage =
    fn_bytes / text_size."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": b"\x00" * 1024},
        sidecar_vm_size=1024,
    )
    cache, _ = _build_stub_cache(fn_bytes=2048, text_size=8192)
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_coverage"].samples[0].value == 0.25  # 2048 / 8192


def test_entropy_metrics_independent_of_baseline(tmp_path, monkeypatch):
    """Entropy metrics are absolute (Shannon entropy in bits) — a
    uniform 256-byte payload yields exactly 8.0 regardless of baseline.
    """
    uniform = bytes(range(256))
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": uniform},
        sidecar_vm_size=len(uniform),
    )
    cache, _ = _build_stub_cache(text_size=99999)  # any value
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert math.isclose(
        by_name["vm_bytecode_entropy"].samples[0].value, 8.0, abs_tol=1e-9,
    )
    assert by_name["vm_bytecode_bigram_entropy"].samples[0].value > 0.0


def test_zero_entropy_flagged_at_scale_floor(tmp_path, monkeypatch):
    """All-zeros payload yields entropy 0 — confirms no NaN / -inf."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": b"\x00" * 512},
        sidecar_vm_size=512,
    )
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_bytecode_entropy"].samples[0].value == 0.0
    assert by_name["vm_bytecode_bigram_entropy"].samples[0].value == 0.0


def test_evidence_carries_numerator_and_denominator(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": b"\xFF" * 300},
        sidecar_vm_size=300,
        sidecar_handler_count=7,
    )
    cache, _ = _build_stub_cache(text_size=4500, fn_bytes=1200)
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    ev = result.metrics[0].samples[0].evidence
    assert ev["vm_section_bytes"] == 300
    assert ev["baseline_filtered_bytes"] == 1200
    assert ev["baseline_total_text_size"] == 4500
    assert ev["virtualized_regions"] == 7
    # filter_rva_count matches the default synthetic sidecar entries.
    assert ev["filter_rva_count"] == 2


# ============================================================================
# Corpus filter
# ============================================================================


def test_untagged_entry_skipped(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["vm"]),
        ("gamma", ["cff"]),  # not vm-tagged → filtered out
    ])
    mocks = _install_mocks(monkeypatch)
    cache, provider = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert len(mocks["build_calls"]) == 1
    assert len(mocks["byte_calls"]) == 1
    # Two baseline calls per processed entry (filtered + total).
    assert len(provider.calls) == 2


def test_no_vm_tagged_entries_reports_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("gamma", ["cff"])])
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no corpus entries tagged 'vm'" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


# ============================================================================
# Failure modes
# ============================================================================


def test_build_failure_propagates_as_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"]), ("beta", ["vm"])])
    _install_mocks(
        monkeypatch,
        build_map={"alpha": BuilderError("exit=1: bad PE")},
    )
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("alpha" in e and "build failed" in e for e in result.errors)
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert "beta" in sample_names
    assert "alpha" not in sample_names


def test_sidecar_missing_vm_section_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_has_vm=False)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no (non-empty) 'vm' section" in e
        or "virtualization pass disabled" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_zero_size_vm_section_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_vm_size=0)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any(
        "non-empty" in e or "virtualization pass disabled" in e
        for e in result.errors
    )


def test_missing_sidecar_errors_entry(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_omit=True)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no sidecar" in e.lower() or "trace-hints" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_pe_reader_failure_reports_entry_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": NotAPeError("bad DOS magic")},
    )
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any(
        "VM bytes read failed" in e and "NotAPeError" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_section_not_found_reports_entry_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": SectionNotFoundError("no section covers RVA")},
    )
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("SectionNotFoundError" in e for e in result.errors)


def test_baseline_measurement_failure_aborts_entry(tmp_path, monkeypatch):
    """A baseline measurement failure cannot produce a density ratio —
    the entry errors cleanly."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["vm"]),
        ("beta",  ["vm"]),
    ])
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache(overrides={
        "alpha": BaselineError("IDA died on baseline"),
    })
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "alpha" in e and "baseline measurement failed" in e
        for e in result.errors
    )
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"beta"}


def test_pre_protected_entry_errors_with_no_baseline_explanation(
    tmp_path, monkeypatch,
):
    """Pre-protected entries have no unprotected source — the
    benchmark refuses to score them rather than producing incomparable
    absolute counts."""
    corpus_root = tmp_path / "corpus"
    bin_dir = corpus_root / "bin"
    bin_dir.mkdir(parents=True)
    pre = bin_dir / "legacy.exe"
    pre.write_bytes(b"\x4d\x5a")

    (corpus_root / "corpus.json").write_text(json.dumps({
        "schema_version": 1,
        "entries": [{
            "name": "legacy",
            "pre_protected": "bin/legacy.exe",
            "tags": ["vm"],
        }],
    }), encoding="utf-8")

    corpus = Corpus.load(corpus_root)
    _install_mocks(monkeypatch)
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "legacy" in e and "pre-protected" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


# ============================================================================
# Cache behaviour at the integration level
# ============================================================================


def test_empty_protected_functions_errors_entry(tmp_path, monkeypatch):
    """A sidecar with no vm-kind entries in ``protected_functions``
    means the filter is empty — benchmark cannot compute density
    against unknowns. Errors cleanly."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_protected_rvas=())
    cache, _ = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no vm-kind entries in protected_functions" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_baseline_cache_reused_across_entries_in_one_run(tmp_path, monkeypatch):
    """Two distinct VM-tagged entries share one baseline cache —
    provider sees each unprotected binary exactly once."""
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["vm"]),
        ("beta",  ["vm"]),
    ])
    _install_mocks(monkeypatch)
    cache, provider = _build_stub_cache()
    bench = vb.VmStaticBenchmark(baseline_cache=cache)
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    # Two entries × two calls each (filtered + total) = 4 calls.
    assert len(provider.calls) == 4
    assert len({call[0].stem for call in provider.calls}) == 2


def test_default_baseline_cache_created_when_none_injected():
    """Registry calls ``cls()`` — a real cache must lazy-create on
    first ``run`` without crashing."""
    bench = vb.VmStaticBenchmark()
    cache = bench._resolve_baseline_cache()
    assert bench._resolve_baseline_cache() is cache
