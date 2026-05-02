"""Unit tests for benchmarks.vm_handler_replay_benchmark.

Mocks ``ensure_protected`` + ``run_handler_replay`` + sidecar. The
sidecar fixture is the same shape :mod:`test_vm_symbolic_benchmark`
uses, so the two slow-tier VM benchmarks share intuition.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

from mx_mcp.benchmarks import vm_handler_replay_benchmark as vhrb
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
from mx_mcp.emulation.unicorn import (
    HandlerReplayResult,
    UnicornNotAvailableError,
)
from mx_mcp.emulation.unicorn.runner import (
    TERM_BUDGET_INSTR,
    TERM_LEFT_HANDLER,
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
        guard=GuardHints(),
        strings=StringHints(),
        iat=IatHints(),
    )


def _completed(instr=60) -> HandlerReplayResult:
    return HandlerReplayResult(
        completed=True, instructions_executed=instr, wall_ms=2,
        termination_reason=TERM_LEFT_HANDLER, last_pc=0x14004030,
        error=None,
    )


def _budget_hit(instr=4096) -> HandlerReplayResult:
    return HandlerReplayResult(
        completed=False, instructions_executed=instr, wall_ms=10,
        termination_reason=TERM_BUDGET_INSTR, last_pc=0x14004020,
        error=None,
    )


def _install_mocks(
    monkeypatch,
    *,
    sidecar_handlers: dict[str, int],
    replay_map: dict[tuple[str, int], HandlerReplayResult] | None = None,
    replay_raises: dict[str, BaseException] | None = None,
):
    build_calls: list[str] = []
    replay_calls: list[tuple[str, int]] = []
    sidecars = {n: _make_sidecar(c) for n, c in sidecar_handlers.items()}

    async def fake_ensure(entry, **kw):
        output_dir: Path = kw["output_dir"]
        build_calls.append(entry.name)
        out = output_dir / f"{entry.name}.mx.exe"
        out.write_bytes(b"\x4d\x5a")
        sidecar_path = out.parent / f"{out.name}.mxtrace.json"
        sidecar_path.write_text(
            sidecars[entry.name].model_dump_json(), encoding="utf-8",
        )
        return ProtectedBuild(
            unprotected_binary=entry.unprotected_binary or out,
            protected_binary=out, sidecar_path=sidecar_path,
            duration_ms=1, stdout_tail="", stderr_tail="",
        )

    def fake_replay(binary_path, handler_rva, handler_size, budget):
        name = binary_path.stem
        if name.endswith(".mx"):
            name = name[: -len(".mx")]
        replay_calls.append((name, handler_rva))
        if replay_raises and name in replay_raises:
            raise replay_raises[name]
        if replay_map and (name, handler_rva) in replay_map:
            return replay_map[(name, handler_rva)]
        return _completed(instr=50)

    monkeypatch.setattr(vhrb, "ensure_protected", fake_ensure)
    monkeypatch.setattr(
        vhrb, "resolve_builder_path", lambda root: root / "fake_builder.exe",
    )
    return {
        "build_calls": build_calls,
        "replay_calls": replay_calls,
        "replay_fn": fake_replay,
    }


# ============================================================================
# Mean instructions
# ============================================================================


def test_mean_instructions_across_handlers(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "alpha", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(4)]
    replay_map = {
        ("alpha", rvas[0]): _completed(instr=20),
        ("alpha", rvas[1]): _completed(instr=40),
        ("alpha", rvas[2]): _completed(instr=60),
        ("alpha", rvas[3]): _completed(instr=80),
    }
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"alpha": 4},
        replay_map=replay_map,
    )
    bench = vhrb.VmHandlerReplayBenchmark(replay_fn=mocks["replay_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))

    by_name = {m.name: m for m in result.metrics}
    metric = by_name["vm_handler_unicorn_mean_instructions"]
    assert metric.direction is MetricDirection.HIGHER_BETTER
    # Mean of {20, 40, 60, 80} = 50.0.
    assert metric.samples[0].value == 50.0
    ev = metric.samples[0].evidence
    assert ev["completed"] == 4
    assert ev["crashed"] == 0


def test_handler_sampling_cap_is_respected(tmp_path, monkeypatch):
    """A 30-handler sidecar with cap=8 → only 8 replays."""
    corpus = _make_corpus(tmp_path, [
        {"name": "big", "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={"big": 30})
    bench = vhrb.VmHandlerReplayBenchmark(
        replay_fn=mocks["replay_fn"], max_handlers_per_entry=8,
    )
    asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert len(mocks["replay_calls"]) == 8


def test_budget_hit_handlers_count_in_mean(tmp_path, monkeypatch):
    """A handler that pegs the cap contributes the cap to the mean —
    fail-closed: a handler we couldn't fully run still pulls the
    mean instruction count up (defence-favourable)."""
    corpus = _make_corpus(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["vm"]},
    ])
    rvas = [0x4000 + i * 0x40 for i in range(3)]
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"a": 3},
        replay_map={
            ("a", rvas[0]): _completed(instr=10),
            ("a", rvas[1]): _budget_hit(instr=4096),
            ("a", rvas[2]): _completed(instr=10),
        },
    )
    bench = vhrb.VmHandlerReplayBenchmark(replay_fn=mocks["replay_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    metric = next(m for m in result.metrics
                  if m.name == "vm_handler_unicorn_mean_instructions")
    # (10 + 4096 + 10) / 3 ≈ 1372.0 → rounded to 1372.0.
    assert metric.samples[0].value == round((10 + 4096 + 10) / 3, 2)


# ============================================================================
# Fail-closed
# ============================================================================


def test_backend_missing_aborts_loop(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "a", "binary": "bin/a.exe", "tags": ["vm"]},
        {"name": "b", "binary": "bin/b.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(
        monkeypatch, sidecar_handlers={"a": 2, "b": 2},
        replay_raises={"a": UnicornNotAvailableError("backend disabled")},
    )
    bench = vhrb.VmHandlerReplayBenchmark(replay_fn=mocks["replay_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert mocks["build_calls"] == ["a"]
    assert any("unicorn backend" in e for e in result.errors)
    for m in result.metrics:
        assert m.samples == []


def test_empty_sidecar_handlers_emits_error(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "no_vm", "binary": "bin/n.exe", "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={"no_vm": 0})
    bench = vhrb.VmHandlerReplayBenchmark(replay_fn=mocks["replay_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("no VM handlers" in e for e in result.errors)


def test_pre_protected_entries_rejected(tmp_path, monkeypatch):
    corpus = _make_corpus(tmp_path, [
        {"name": "legacy", "pre_protected": "legacy/old.exe",
         "tags": ["vm"]},
    ])
    mocks = _install_mocks(monkeypatch, sidecar_handlers={})
    bench = vhrb.VmHandlerReplayBenchmark(replay_fn=mocks["replay_fn"])
    result = asyncio.run(bench.run(corpus, _fake_session(tmp_path)))
    assert any("pre-protected" in e for e in result.errors)


# ============================================================================
# Metadata
# ============================================================================


def test_category_and_tier_are_slow_vm():
    bench = vhrb.VmHandlerReplayBenchmark()
    assert bench.category == "vm"
    assert bench.tier == "slow"
    assert "vm" in bench.corpus_tags
