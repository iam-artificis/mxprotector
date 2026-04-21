"""Unit tests for ``deobfuscation.mba.extractor``.

No real angr invocation — we stub the angr / claripy modules through
the lazy-import seam the extractor uses, then assert the state-picking
and output-reading logic.

A parallel integration test against a real PE lives in
``scripts/_smoke_vm_mba.py`` (manual).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from mx_mcp.deobfuscation.mba import extractor as ex
from mx_mcp.deobfuscation.mba.extractor import (
    ExpressionBudget,
    ExtractorUnavailableError,
    extract_handler_expression,
)


# ============================================================================
# ExpressionBudget validation
# ============================================================================


def test_budget_defaults_positive():
    b = ExpressionBudget()
    assert b.max_wall_clock_s > 0
    assert b.max_steps > 0


@pytest.mark.parametrize("kwargs", [
    {"max_wall_clock_s": 0},
    {"max_wall_clock_s": -1},
    {"max_steps": 0},
    {"max_steps": -2},
])
def test_budget_rejects_nonpositive(kwargs):
    with pytest.raises(ValueError):
        ExpressionBudget(**kwargs)


# ============================================================================
# Backend availability
# ============================================================================


def _reset(monkeypatch):
    monkeypatch.setattr(ex, "_angr_module", None)
    monkeypatch.setattr(ex, "_claripy_module", None)


def test_env_kill_switch_raises(monkeypatch):
    _reset(monkeypatch)
    monkeypatch.setenv(ex._DISABLE_ENV_VAR, "1")
    with pytest.raises(ExtractorUnavailableError, match="disabled via"):
        ex._load_angr_stack()


def test_missing_angr_raises(monkeypatch):
    _reset(monkeypatch)
    monkeypatch.delenv(ex._DISABLE_ENV_VAR, raising=False)

    def fake_import(name):
        raise ImportError(f"no module {name}")

    monkeypatch.setattr(ex.importlib, "import_module", fake_import)
    with pytest.raises(ExtractorUnavailableError, match="not installed"):
        ex._load_angr_stack()


# ============================================================================
# extract_handler_expression — fake angr
# ============================================================================


class _FakeRegs:
    """``state.regs`` stand-in. All unknown attributes return the
    given ``default`` so a handler that never writes its output
    register still reads back *something*."""

    def __init__(self, *, default):
        self._by_name: dict[str, object] = {}
        self._default = default

    def __setattr__(self, name, value):
        if name.startswith("_"):
            object.__setattr__(self, name, value)
        else:
            self._by_name[name] = value

    def __getattr__(self, name):
        if name in self._by_name:
            return self._by_name[name]
        return self._default


class _FakeSimManager:
    """Sim manager fake with configurable step behaviour.

    Default: one step empties ``active`` (simulates a handler that
    returned after a single basic block).
    ``persist=True``: ``step`` is a no-op; ``active`` keeps whatever
    state the test seeded. Useful for exercising the "budget hit
    with active states still alive" code path.
    """

    def __init__(self, *, deadended=None, active=None, errored=None,
                 persist=False):
        self.deadended = deadended or []
        self.active = active or []
        self.errored = errored or []
        self._steps = 0
        self._persist = persist

    def step(self):
        self._steps += 1
        if not self._persist:
            self.active = []


class _FakeState:
    def __init__(self, regs):
        self.regs = regs


class _FakeFactory:
    def __init__(self, *, state, deadended=None, active=None, errored=None,
                 persist=False):
        self._state = state
        self._deadended = deadended
        self._active = active
        self._errored = errored
        self._persist = persist

    def blank_state(self, *, addr, add_options=None):
        return self._state

    def simulation_manager(self, state):
        return _FakeSimManager(
            deadended=self._deadended,
            active=self._active,
            errored=self._errored,
            persist=self._persist,
        )


@dataclass
class _FakeAst:
    op: str = "BVV"
    args: tuple = ()
    depth: int = 1


def _fake_ast(depth=1):
    root = _FakeAst(depth=depth)
    node = root
    for _ in range(depth - 1):
        child = _FakeAst(depth=1)
        node.args = (child,)
        node = child
    return root


def _install_fake_angr(monkeypatch, *, output_register_value=None,
                       deadended=None, active=None, errored=None,
                       persist_sim=False):
    """Wire fake ``angr`` + ``claripy`` modules into the extractor.

    ``persist_sim=True`` keeps the fake ``simgr.active`` population
    across ``step()`` calls, emulating the "budget hit with paths
    still alive" path.
    """
    regs = _FakeRegs(default=_fake_ast(depth=2))
    if output_register_value is not None:
        setattr(regs, "rax", output_register_value)
    state = _FakeState(regs)

    class _FakeMainObj:
        mapped_base = 0x400000

    class _FakeLoader:
        main_object = _FakeMainObj()

    class _FakeProject:
        def __init__(self, path, **kwargs):
            self.loader = _FakeLoader()
            self.factory = _FakeFactory(
                state=state, deadended=deadended,
                active=active, errored=errored,
                persist=persist_sim,
            )

    class _FakeAngr:
        Project = _FakeProject

    class _FakeClaripy:
        @staticmethod
        def BVS(name, width):
            return _FakeAst(op="BVS", args=(), depth=1)

    monkeypatch.setattr(ex, "_angr_module", _FakeAngr)
    monkeypatch.setattr(ex, "_claripy_module", _FakeClaripy)
    monkeypatch.delenv(ex._DISABLE_ENV_VAR, raising=False)


def test_extracts_deadend_state_output(monkeypatch, tmp_path):
    output = _fake_ast(depth=5)
    deadend_state = _FakeState(_FakeRegs(default=output))
    _install_fake_angr(
        monkeypatch,
        output_register_value=output,
        deadended=[deadend_state],
    )
    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x4000, handler_size=0x40,
        handler_opcode="add",
        budget=ExpressionBudget(max_steps=5, max_wall_clock_s=1.0),
    )
    assert expr.handler_rva == 0x4000
    # Default extractor now annotates the chosen register onto the
    # opcode ("<opcode>@<reg>"); the base opcode is preserved as
    # the prefix.
    assert expr.handler_opcode.startswith("add@")
    assert expr.ast_nodes >= 1
    assert expr.ast_depth == 5


def test_falls_back_to_active_state(monkeypatch, tmp_path):
    """No deadended, only active = extractor reads from an active
    state (the budget-hit case).

    ``persist_sim=True`` keeps the fake's ``active`` non-empty
    across the step loop so the budget cap fires and leaves the
    state available for ``_pick_state``."""
    output = _fake_ast(depth=3)
    active_state = _FakeState(_FakeRegs(default=output))
    _install_fake_angr(
        monkeypatch,
        output_register_value=output,
        active=[active_state],
        persist_sim=True,
    )
    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x5000, handler_size=0x20,
        budget=ExpressionBudget(max_steps=2, max_wall_clock_s=1.0),
    )
    assert expr.ast_depth == 3


def test_falls_back_to_initial_state_when_no_states(monkeypatch, tmp_path):
    """Empty simgr (no active / deadended / errored) still returns
    a result — reads from the initial state."""
    _install_fake_angr(monkeypatch)
    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x6000, handler_size=0x10,
        budget=ExpressionBudget(max_steps=2, max_wall_clock_s=1.0),
    )
    # Default mock regs return a 2-depth AST → ast_depth=2.
    assert expr.ast_depth >= 1


def test_custom_output_register(monkeypatch, tmp_path):
    output = _fake_ast(depth=7)
    state = _FakeState(_FakeRegs(default=_fake_ast(depth=1)))
    setattr(state.regs, "r14", output)
    _install_fake_angr(monkeypatch, deadended=[state])
    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x7000, handler_size=0x30,
        output_register="r14",
        budget=ExpressionBudget(max_steps=3, max_wall_clock_s=1.0),
    )
    assert expr.ast_depth == 7


def test_unknown_output_register_returns_fallback(monkeypatch, tmp_path):
    """A typoed register name doesn't crash — fallback synthetic
    symbol keeps the pipeline moving."""
    # Make the fake regs raise AttributeError on the mistyped name.
    class _StrictRegs:
        def __getattr__(self, name):
            raise AttributeError(name)

    state = _FakeState(_StrictRegs())

    class _FakeMainObj:
        mapped_base = 0x400000

    class _FakeLoader:
        main_object = _FakeMainObj()

    class _FakeFactoryStrict:
        def blank_state(self, *, addr, add_options=None):
            return state

        def simulation_manager(self, state):
            return _FakeSimManager(deadended=[state])

    class _FakeProject:
        def __init__(self, path, **kwargs):
            self.loader = _FakeLoader()
            self.factory = _FakeFactoryStrict()

    class _FakeAngr:
        Project = _FakeProject

    class _FakeClaripy:
        @staticmethod
        def BVS(name, width):
            return _FakeAst(op="BVS", args=(), depth=1)

    monkeypatch.setattr(ex, "_angr_module", _FakeAngr)
    monkeypatch.setattr(ex, "_claripy_module", _FakeClaripy)
    # Also patch the module-level claripy import used in the fallback
    # branch inside the extractor.
    import sys
    monkeypatch.setitem(sys.modules, "claripy", _FakeClaripy)

    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x8000, handler_size=0x10,
        output_register="xyz_bogus",
        budget=ExpressionBudget(max_steps=1, max_wall_clock_s=1.0),
    )
    assert expr.ast_nodes >= 1


def test_step_exception_is_absorbed(monkeypatch, tmp_path):
    """A mid-simulation exception doesn't propagate — the loop
    terminates cleanly and the extractor still returns whatever
    the initial state had in the output register."""
    output = _fake_ast(depth=2)
    state = _FakeState(_FakeRegs(default=output))

    class _BlowUpSim:
        def __init__(self):
            self.deadended = []
            self.active = [state]
            self.errored = []

        def step(self):
            raise RuntimeError("mid-step blow-up")

    class _Factory:
        def blank_state(self, *, addr, add_options=None):
            return state

        def simulation_manager(self, _):
            return _BlowUpSim()

    class _Project:
        def __init__(self, path, **kwargs):
            class _L:
                class main_object:
                    mapped_base = 0x400000
            self.loader = _L()
            self.factory = _Factory()

    class _Angr:
        Project = _Project

    class _Claripy:
        @staticmethod
        def BVS(name, width):
            return _FakeAst(op="BVS", args=(), depth=1)

    monkeypatch.setattr(ex, "_angr_module", _Angr)
    monkeypatch.setattr(ex, "_claripy_module", _Claripy)
    monkeypatch.delenv(ex._DISABLE_ENV_VAR, raising=False)

    expr = extract_handler_expression(
        tmp_path / "x.exe", handler_rva=0x9000, handler_size=0x10,
        budget=ExpressionBudget(max_steps=5, max_wall_clock_s=1.0),
    )
    # Post-exception we still got a meaningful expression (from the
    # active/initial state).
    assert expr.ast_depth >= 1
