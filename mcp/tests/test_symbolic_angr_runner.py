"""Unit tests for symbolic.angr.runner.

Covers the backend loader + :func:`analyse_handler` outcome
classification without touching the real angr. We stub the module
import via :mod:`importlib` so the tests stay fast and deterministic
even on hosts that have the heavy backend installed.

Test layers:

1. ``SymbolicBudget`` validation.
2. Backend-availability: missing angr, kill-switch env var.
3. Outcome classification on a mock angr: cleanly finished, budget
   hit (steps / wall / paths), state init failure, step exception.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.symbolic.angr import runner
from mx_mcp.symbolic.angr.budget import SymbolicBudget
from mx_mcp.symbolic.angr.runner import (
    AngrNotAvailableError,
    HandlerAnalysisResult,
    analyse_handler,
)


# ============================================================================
# SymbolicBudget
# ============================================================================


def test_budget_defaults_are_sane():
    b = SymbolicBudget()
    assert b.max_wall_clock_s > 0
    assert b.max_steps > 0
    assert b.max_paths > 0


@pytest.mark.parametrize("kwargs", [
    {"max_wall_clock_s": 0.0},
    {"max_wall_clock_s": -1.0},
    {"max_steps": 0},
    {"max_steps": -5},
    {"max_paths": 0},
])
def test_budget_rejects_nonpositive(kwargs):
    with pytest.raises(ValueError):
        SymbolicBudget(**kwargs)


# ============================================================================
# Backend loader
# ============================================================================


def _reset_loader_cache(monkeypatch):
    monkeypatch.setattr(runner, "_angr_module", None)
    monkeypatch.setattr(runner, "_cle_module", None)


def test_env_kill_switch_raises_not_available(monkeypatch):
    _reset_loader_cache(monkeypatch)
    monkeypatch.setenv(runner._DISABLE_ENV_VAR, "1")
    with pytest.raises(AngrNotAvailableError, match="disabled via"):
        runner._load_angr()


def test_missing_import_raises_not_available(monkeypatch):
    _reset_loader_cache(monkeypatch)
    monkeypatch.delenv(runner._DISABLE_ENV_VAR, raising=False)

    def fake_import(name):
        raise ImportError(f"no module named {name}")

    monkeypatch.setattr(runner.importlib, "import_module", fake_import)
    with pytest.raises(AngrNotAvailableError, match="not installed"):
        runner._load_angr()


# ============================================================================
# analyse_handler — mocked angr
# ============================================================================


class _FakeSimManager:
    """Drives a scripted sequence of active-state lists per step.

    ``states_per_step[0]`` = state count at the very start (pre-loop).
    Subsequent indices = the count *after* step N. When the script
    runs out, ``step`` leaves ``active`` empty — the loop terminates
    cleanly.
    """

    def __init__(self, states_per_step):
        self._script = list(states_per_step)
        self.active = [object()] * (self._script[0] if self._script else 0)
        self._step_calls = 0

    def step(self):
        self._step_calls += 1
        if self._step_calls < len(self._script):
            self.active = [object()] * self._script[self._step_calls]
        else:
            self.active = []


class _FakeFactory:
    def __init__(self, states_per_step, raise_on_step=None):
        self._states_per_step = states_per_step
        self._raise_on_step = raise_on_step

    def blank_state(self, *, addr, add_options=None):
        self._last_addr = addr
        return object()

    def simulation_manager(self, state):
        simgr = _FakeSimManager(self._states_per_step)
        if self._raise_on_step is not None:
            orig = simgr.step
            count = 0

            def step():
                nonlocal count
                count += 1
                if count == self._raise_on_step:
                    raise RuntimeError("mock angr blew up")
                orig()

            simgr.step = step
        return simgr


class _FakeMainObject:
    mapped_base = 0x400000


class _FakeLoader:
    main_object = _FakeMainObject()


class _FakeProject:
    def __init__(self, path, states_per_step, raise_on_step=None,
                 state_raises=False):
        self.path = path
        self.loader = _FakeLoader()
        if state_raises:
            class Bad:
                def blank_state(self, *, addr, add_options=None):
                    raise RuntimeError("state init blew up")

                def simulation_manager(self, state):
                    raise AssertionError("should not reach")
            self.factory = Bad()
        else:
            self.factory = _FakeFactory(
                states_per_step, raise_on_step=raise_on_step,
            )


def _install_fake_angr(monkeypatch, *, states_per_step, raise_on_step=None,
                      project_raises=False, state_raises=False):
    class FakeAngr:
        @staticmethod
        def Project(path, **kwargs):
            if project_raises:
                raise RuntimeError("loader blew up")
            return _FakeProject(
                path, states_per_step,
                raise_on_step=raise_on_step,
                state_raises=state_raises,
            )

    monkeypatch.setattr(runner, "_angr_module", FakeAngr)
    monkeypatch.setattr(runner, "_cle_module", object())
    monkeypatch.delenv(runner._DISABLE_ENV_VAR, raising=False)


def test_cleanly_finished_summarised(monkeypatch, tmp_path):
    # Script: 1 active → 1 active → 0 active (two steps, then empty).
    _install_fake_angr(monkeypatch, states_per_step=[1, 1, 0])
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert isinstance(res, HandlerAnalysisResult)
    assert res.summarised is True
    assert res.termination_reason == "cleanly_finished"
    assert res.steps == 2
    assert res.error is None


def test_budget_steps_exhausted(monkeypatch, tmp_path):
    # Active forever → loop will hit the step cap.
    _install_fake_angr(monkeypatch, states_per_step=[1] * 50)
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(max_steps=3, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.summarised is False
    assert res.termination_reason == "budget_steps"
    assert res.steps == 3


def test_budget_paths_exhausted(monkeypatch, tmp_path):
    # States blow up to 100 after the first step; cap at 5.
    _install_fake_angr(monkeypatch, states_per_step=[1, 100, 100, 100])
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(max_steps=50, max_wall_clock_s=5.0, max_paths=5),
    )
    assert res.summarised is False
    assert res.termination_reason == "budget_paths"
    # paths_peak reflects the observed max.
    assert res.paths_explored >= 5


def test_budget_wall_exhausted(monkeypatch, tmp_path):
    """A slow ``step`` trips the wall-clock cap.

    We simulate slowness by patching ``time.monotonic`` to return a
    sequence that crosses the cap on the second call.
    """
    _install_fake_angr(monkeypatch, states_per_step=[1] * 20)

    times = iter([0.0, 0.001, 0.002, 100.0, 100.0, 100.0])

    def fake_monotonic():
        try:
            return next(times)
        except StopIteration:
            return 200.0

    monkeypatch.setattr(runner.time, "monotonic", fake_monotonic)
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(max_steps=50, max_wall_clock_s=1.0, max_paths=50),
    )
    assert res.summarised is False
    assert res.termination_reason == "budget_wall"


def test_project_load_error_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(monkeypatch, states_per_step=[1, 0], project_raises=True)
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(),
    )
    assert res.summarised is False
    assert res.termination_reason == "errored"
    assert "project_load_failed" in (res.error or "")


def test_state_init_error_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(monkeypatch, states_per_step=[1, 0], state_raises=True)
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(),
    )
    assert res.summarised is False
    assert res.termination_reason == "errored"
    assert "state_init_failed" in (res.error or "")


def test_step_exception_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(
        monkeypatch,
        states_per_step=[1, 1, 1, 0],
        raise_on_step=2,  # blow up on the second step() call
    )
    res = analyse_handler(
        tmp_path / "x.exe", handler_rva=0x1000, handler_size=0x40,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.summarised is False
    assert res.termination_reason == "errored"
    assert "step_raised" in (res.error or "")
    # steps before the crash are preserved (so evidence can still hint
    # at how far angr got).
    assert res.steps >= 1


def test_analyse_handler_surfaces_missing_backend(monkeypatch, tmp_path: Path):
    _reset_loader_cache(monkeypatch)
    monkeypatch.setenv(runner._DISABLE_ENV_VAR, "1")
    with pytest.raises(AngrNotAvailableError):
        analyse_handler(
            tmp_path / "x.exe", handler_rva=0, handler_size=0,
            budget=SymbolicBudget(),
        )
