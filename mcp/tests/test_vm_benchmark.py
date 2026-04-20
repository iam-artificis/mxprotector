"""Unit tests for benchmarks.vm_benchmark.

Patches ``build_protected`` and ``read_section_bytes`` at the
benchmark module so tests neither invoke the real builder nor parse a
real PE header. Mirrors ``test_cff_benchmark`` structurally — the
helper sets up a synthetic sidecar + byte payload keyed by corpus
entry name and returns a ``mocks`` dict so each test can assert on the
calls that were made.
"""

from __future__ import annotations

import asyncio
import json
import math
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import vm_benchmark as vb
from mx_mcp.common.benchmark_base import BenchmarkResult, MetricDirection
from mx_mcp.common.builder import BuilderError, ProtectedBuild
from mx_mcp.common.corpus import Corpus
from mx_mcp.common.pe_reader import NotAPeError, SectionNotFoundError


# ============================================================================
# Corpus helper
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
# Mock factories
# ============================================================================


_DEFAULT_VM_RVA = 0x30000
_DEFAULT_VM_SIZE = 0x800
_DEFAULT_HANDLER_COUNT = 3


def _write_synthetic_sidecar(
    sidecar_path: Path,
    *,
    vm_rva: int = _DEFAULT_VM_RVA,
    vm_size: int = _DEFAULT_VM_SIZE,
    handler_count: int = _DEFAULT_HANDLER_COUNT,
    include_vm: bool = True,
) -> None:
    """Write a pydantic-valid sidecar next to a protected output.

    Knobs:
      * ``include_vm=False`` — omits the 'vm' entry from ``sections``.
      * ``vm_size=0`` — section present but empty (virtualization pass
        emitted nothing).
      * ``handler_count`` — controls ``vm.handlers`` length; fed into
        the ``vm_region_count`` metric.
    """
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
) -> dict:
    """Install monkey-patches keyed by corpus-entry name.

    ``bytes_map`` supplies the synthetic VM bytes per entry — exceptions
    in the map propagate through ``read_section_bytes`` as if the PE
    was malformed. Missing keys default to a high-entropy random-ish
    payload sized to ``sidecar_vm_size``.
    """
    build_calls: list[Path] = []
    byte_calls: list[tuple[Path, int, int]] = []

    async def fake_build(**kw):
        unprotected: Path = kw["unprotected"]
        output: Path = kw["output"]
        build_calls.append(unprotected)

        behaviour = (build_map or {}).get(unprotected.stem)
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
            )
        return ProtectedBuild(
            unprotected_binary=unprotected,
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
        # Default: deterministic high-entropy payload so the entropy
        # metric is non-zero but reproducible.
        return bytes((i * 131 + 7) & 0xFF for i in range(size))

    monkeypatch.setattr(vb, "build_protected", fake_build)
    monkeypatch.setattr(vb, "read_section_bytes", fake_read_section_bytes)
    monkeypatch.setattr(vb, "resolve_builder_path",
                        lambda root: root / "fake_builder.exe")

    return {"build_calls": build_calls, "byte_calls": byte_calls}


# ============================================================================
# Happy path + filter
# ============================================================================


def test_happy_path_emits_one_sample_per_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"]), ("beta", ["vm"])])
    _install_mocks(monkeypatch)
    bench = vb.VmStaticBenchmark()

    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert isinstance(result, BenchmarkResult)
    assert result.benchmark == "vm_static"
    assert result.category == "vm"
    assert result.tier == "fast"
    assert result.errors == []

    assert len(result.metrics) == 4
    for m in result.metrics:
        assert m.direction is MetricDirection.HIGHER_BETTER
        assert len(m.samples) == 2

    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert sample_names == {"alpha", "beta"}


def test_untagged_entry_skipped(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        ("alpha", ["vm"]),
        ("gamma", ["cff"]),   # not vm-tagged → filtered out.
    ])
    mocks = _install_mocks(monkeypatch)
    bench = vb.VmStaticBenchmark()
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert len(mocks["build_calls"]) == 1
    assert len(mocks["byte_calls"]) == 1


def test_no_vm_tagged_entries_reports_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("gamma", ["cff"])])
    _install_mocks(monkeypatch)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no corpus entries tagged 'vm'" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


# ============================================================================
# Metric values + correctness
# ============================================================================


def test_metric_values_match_inputs(tmp_path: Path, monkeypatch):
    """Exact-value roundtrip: a uniform byte-distribution payload yields
    maximal Shannon entropy; section size and region count surface
    unchanged from the synthetic sidecar / bytes."""
    # 256 bytes each occurring exactly once → byte entropy = 8 bits.
    uniform = bytes(range(256))
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": uniform},
        sidecar_vm_size=len(uniform),
        sidecar_handler_count=5,
    )
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    assert math.isclose(by_name["vm_bytecode_entropy"].samples[0].value, 8.0, abs_tol=1e-9)
    assert by_name["vm_bytecode_bytes"].samples[0].value == 256
    assert by_name["vm_region_count"].samples[0].value == 5
    # Bigram entropy on a rotating-cycle payload like range(256) is
    # non-zero but well under the theoretical 16 — sanity check only.
    assert by_name["vm_bytecode_bigram_entropy"].samples[0].value > 0.0


def test_zero_entropy_flagged_at_scale_floor(tmp_path: Path, monkeypatch):
    """An all-zeros payload produces entropy 0 — confirms our floor
    handling (not NaN, not -inf)."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": b"\x00" * 512},
        sidecar_vm_size=512,
    )
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_bytecode_entropy"].samples[0].value == 0.0
    assert by_name["vm_bytecode_bigram_entropy"].samples[0].value == 0.0


# ============================================================================
# Error paths (fail-closed)
# ============================================================================


def test_build_failure_propagates_as_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"]), ("beta", ["vm"])])
    _install_mocks(
        monkeypatch,
        build_map={"alpha": BuilderError("exit=1: bad PE")},
    )
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("alpha" in e and "build failed" in e for e in result.errors)
    # beta still produced samples.
    sample_names = {s.sample_name for s in result.metrics[0].samples}
    assert "beta" in sample_names
    assert "alpha" not in sample_names


def test_sidecar_missing_vm_section_errors_entry(tmp_path: Path, monkeypatch):
    """Builder ran with ``--no-vm`` — no 'vm' entry in sidecar sections."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_has_vm=False)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any(
        "no (non-empty) 'vm' section" in e or "virtualization pass disabled" in e
        for e in result.errors
    )
    for m in result.metrics:
        assert m.samples == []


def test_zero_size_vm_section_errors_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_vm_size=0)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("non-empty" in e or "virtualization pass disabled" in e
               for e in result.errors)


def test_missing_sidecar_errors_entry(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_omit=True)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    assert any("no sidecar" in e.lower() or "trace-hints" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_pe_reader_failure_reports_entry_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": NotAPeError("bad DOS magic")},
    )
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("VM bytes read failed" in e and "NotAPeError" in e
               for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_section_not_found_reports_entry_error(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(
        monkeypatch,
        bytes_map={"alpha": SectionNotFoundError("no section covers RVA")},
    )
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("SectionNotFoundError" in e for e in result.errors)


# ============================================================================
# Handler count is sourced from the sidecar, not the byte scan.
# ============================================================================


def test_region_count_reflects_sidecar_handlers(tmp_path: Path, monkeypatch):
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_handler_count=7)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_region_count"].samples[0].value == 7


def test_zero_handlers_reported_as_zero(tmp_path: Path, monkeypatch):
    """Section present (so we still read bytes) but handler list empty —
    covers the "sidecar partial" edge rather than dropping the entry."""
    corpus = _make_corpus(tmp_path, [("alpha", ["vm"])])
    _install_mocks(monkeypatch, sidecar_handler_count=0)
    bench = vb.VmStaticBenchmark()
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    by_name = {m.name: m for m in result.metrics}
    assert by_name["vm_region_count"].samples[0].value == 0
    # Quality metrics still emitted.
    assert by_name["vm_bytecode_entropy"].samples[0].value > 0.0
