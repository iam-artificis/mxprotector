"""Unit tests for symbolic.angr.oep_reach.

Mirrors the test layout of :mod:`test_symbolic_angr_runner`: stub the
angr module via ``importlib`` so the tests stay fast and deterministic
even on hosts that have the heavy backend installed. Outcome shapes
covered:

1. OEP reached on the first iteration (steps == 0).
2. OEP reached after several steps.
3. Budget exhaustion: steps / wall / paths.
4. Active queue draining without ever hitting OEP (``exhausted``).
5. Per-phase angr crashes: project load, state init, mid-step.
6. Backend-missing surfaces :class:`AngrNotAvailableError`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mx_mcp.symbolic.angr import oep_reach
from mx_mcp.symbolic.angr import runner
from mx_mcp.symbolic.angr.budget import SymbolicBudget
from mx_mcp.symbolic.angr.oep_reach import (
    AngrNotAvailableError,
    OepReachResult,
    TERM_BUDGET_PATHS,
    TERM_BUDGET_STEPS,
    TERM_BUDGET_WALL,
    TERM_ERRORED,
    TERM_EXHAUSTED,
    TERM_REACHED,
    analyse_oep_reach,
)


# ============================================================================
# Fake angr scaffolding — modelled after test_symbolic_angr_runner so
# the two suites share intuition, but with per-step IP control because
# OEP-reach checks ``state.addr`` on every iteration.
# ============================================================================


class _FakeState:
    """One angr active state. Carries a (mock) program counter."""

    def __init__(self, addr: int) -> None:
        self.addr = addr


class _FakeSimManager:
    """Drives a scripted sequence of (count, addr) pairs.

    Each script entry produces ``count`` active states all sitting at
    ``addr``. The first entry is the pre-loop state; subsequent
    entries describe the state after step N. When the script runs out
    the active queue empties.
    """

    def __init__(self, addrs_per_step):
        self._script = list(addrs_per_step)
        self._step_calls = 0
        self.active = self._materialise(0)

    def step(self):
        self._step_calls += 1
        self.active = self._materialise(self._step_calls)

    def _materialise(self, idx: int) -> list[_FakeState]:
        if idx >= len(self._script):
            return []
        count, addr = self._script[idx]
        return [_FakeState(addr) for _ in range(count)]


class _FakeFactory:
    def __init__(self, script, raise_on_step=None):
        self._script = script
        self._raise_on_step = raise_on_step

    def entry_state(self, *, add_options=None):
        return object()

    def simulation_manager(self, state):
        simgr = _FakeSimManager(self._script)
        if self._raise_on_step is not None:
            orig_step = simgr.step
            count = 0

            def step():
                nonlocal count
                count += 1
                if count == self._raise_on_step:
                    raise RuntimeError("mock angr blew up")
                orig_step()

            simgr.step = step
        return simgr


class _FakeMainObject:
    mapped_base = 0x400000


class _FakeLoader:
    main_object = _FakeMainObject()


class _FakeProject:
    def __init__(self, path, script, raise_on_step=None,
                 state_raises=False):
        self.path = path
        self.loader = _FakeLoader()
        if state_raises:
            class Bad:
                def entry_state(self, *, add_options=None):
                    raise RuntimeError("state init blew up")

                def simulation_manager(self, state):
                    raise AssertionError("should not reach")
            self.factory = Bad()
        else:
            self.factory = _FakeFactory(
                script, raise_on_step=raise_on_step,
            )


def _install_fake_angr(monkeypatch, *, script, raise_on_step=None,
                      project_raises=False, state_raises=False):
    class FakeAngr:
        @staticmethod
        def Project(path, **kwargs):
            if project_raises:
                raise RuntimeError("loader blew up")
            return _FakeProject(
                path, script,
                raise_on_step=raise_on_step,
                state_raises=state_raises,
            )

    monkeypatch.setattr(runner, "_angr_module", FakeAngr)
    monkeypatch.setattr(runner, "_cle_module", object())
    monkeypatch.delenv(runner._DISABLE_ENV_VAR, raising=False)


# ============================================================================
# Reached paths
# ============================================================================


_OEP_RVA = 0x1234
_OEP_ABS = _FakeMainObject.mapped_base + _OEP_RVA  # 0x401234


def test_reached_on_first_iteration_costs_zero_steps(monkeypatch, tmp_path):
    """A state already sitting at the OEP pre-step → step count = 0.

    Important property: the hit check runs at the TOP of the loop, so
    a build whose stub jumps straight to OEP gets a 0-step reading
    (the lowest possible defence score).
    """
    _install_fake_angr(monkeypatch, script=[(1, _OEP_ABS)])
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert isinstance(res, OepReachResult)
    assert res.reached is True
    assert res.termination_reason == TERM_REACHED
    assert res.steps == 0
    assert res.error is None


def test_reached_after_several_steps(monkeypatch, tmp_path):
    """Walk the stub: stay off-OEP for two steps, then arrive on the third."""
    _install_fake_angr(monkeypatch, script=[
        (1, 0x500000),  # pre-loop
        (1, 0x500010),  # after step 1
        (1, 0x500020),  # after step 2
        (1, _OEP_ABS),  # after step 3 — hit
    ])
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is True
    assert res.termination_reason == TERM_REACHED
    assert res.steps == 3


# ============================================================================
# Budget exhaustion
# ============================================================================


def test_budget_steps_exhausted(monkeypatch, tmp_path):
    """Stub keeps walking off-OEP forever → cap on max_steps trips."""
    _install_fake_angr(monkeypatch, script=[(1, 0x500000)] * 50)
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=4, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_BUDGET_STEPS
    # steps reports the cap that tripped — feeds straight into the
    # HIGHER_BETTER metric so attacker-resistant builds peg the cap.
    assert res.steps == 4


def test_budget_paths_exhausted(monkeypatch, tmp_path):
    """Path explosion (>= max_paths active) trips the paths cap."""
    _install_fake_angr(monkeypatch, script=[
        (1, 0x500000),
        (200, 0x500010),  # blow up the active queue
        (200, 0x500020),
    ])
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=50, max_wall_clock_s=5.0, max_paths=10),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_BUDGET_PATHS
    # paths_peak reflects the observed maximum — the runner records
    # the post-step peak, so once states fork past the cap it pins.
    assert res.paths_explored >= 10


def test_budget_wall_exhausted(monkeypatch, tmp_path):
    """A slow ``step`` trips the wall-clock cap on the second iteration."""
    _install_fake_angr(monkeypatch, script=[(1, 0x500000)] * 20)

    times = iter([0.0, 0.001, 0.002, 100.0, 100.0, 100.0])

    def fake_monotonic():
        try:
            return next(times)
        except StopIteration:
            return 200.0

    monkeypatch.setattr(oep_reach.time, "monotonic", fake_monotonic)
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=50, max_wall_clock_s=1.0, max_paths=50),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_BUDGET_WALL


def test_active_queue_drains_without_reaching_oep(monkeypatch, tmp_path):
    """Stub explores a few states, every one deadends → ``exhausted``.

    The metric uses the actual step count (not the cap) — evidence
    reflects how far angr actually got even though the score still
    reads as "not reached" on the FALSE_BEST sibling metric.
    """
    _install_fake_angr(monkeypatch, script=[
        (2, 0x500000),
        (1, 0x500010),
        (0, 0x500020),  # active drains here
    ])
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=50, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_EXHAUSTED
    # Two productive steps before the queue emptied.
    assert res.steps == 2


# ============================================================================
# Errored paths — fail-closed
# ============================================================================


def test_project_load_error_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(monkeypatch, script=[], project_raises=True)
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_ERRORED
    assert "project_load_failed" in (res.error or "")


def test_state_init_error_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(monkeypatch, script=[(1, 0x500000)], state_raises=True)
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_ERRORED
    assert "state_init_failed" in (res.error or "")
    # Fail-closed: errored result reports the budget cap so it cannot
    # accidentally inflate the defence score relative to budget hits.
    assert res.steps == 10


def test_step_exception_reported_as_errored(monkeypatch, tmp_path):
    _install_fake_angr(
        monkeypatch,
        script=[(1, 0x500000)] * 5,
        raise_on_step=2,  # blow up on the second step()
    )
    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is False
    assert res.termination_reason == TERM_ERRORED
    assert "step_raised" in (res.error or "")
    # Fail-closed step count: max(actual, budget cap).
    assert res.steps == 10


def test_analyse_oep_reach_surfaces_missing_backend(monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "_angr_module", None)
    monkeypatch.setattr(runner, "_cle_module", None)
    monkeypatch.setenv(runner._DISABLE_ENV_VAR, "1")
    with pytest.raises(AngrNotAvailableError):
        analyse_oep_reach(
            tmp_path / "x.exe",
            target_oep_rva=0,
            budget=SymbolicBudget(),
        )


# ============================================================================
# Robustness — non-int IP fakes do not hallucinate hits
# ============================================================================


def test_non_int_state_addr_is_ignored(monkeypatch, tmp_path):
    """A state whose ``addr`` is not int-coercible must not match.

    Defends against partial test fakes / future angr versions that
    expose claripy-typed IPs on active states.
    """
    class _BadState:
        addr = "not an int"

    class _BadSim:
        def __init__(self):
            self.active = [_BadState()]
            self._calls = 0

        def step(self):
            self._calls += 1
            self.active = []  # drain after one step

    class _BadFactory:
        def entry_state(self, *, add_options=None):
            return object()

        def simulation_manager(self, state):
            return _BadSim()

    class _BadProject:
        def __init__(self, path, **kwargs):
            self.loader = _FakeLoader()
            self.factory = _BadFactory()

    class FakeAngr:
        @staticmethod
        def Project(path, **kwargs):
            return _BadProject(path)

    monkeypatch.setattr(runner, "_angr_module", FakeAngr)
    monkeypatch.setattr(runner, "_cle_module", object())
    monkeypatch.delenv(runner._DISABLE_ENV_VAR, raising=False)

    res = analyse_oep_reach(
        tmp_path / "x.exe", target_oep_rva=_OEP_RVA,
        budget=SymbolicBudget(max_steps=10, max_wall_clock_s=5.0, max_paths=50),
    )
    assert res.reached is False
    # Active drained on first step → exhausted, not reached.
    assert res.termination_reason == TERM_EXHAUSTED
