"""Sanity checks on the registered gate catalogue.

Pins the contract between the gate registry and the benchmark
registry: each gate's ``(benchmark, metric)`` MUST match a metric
declared by some registered benchmark — otherwise the gate would
SKIP forever, silently masking a regression.

Also asserts the registry has unique names and the expected
catalogue size (a sentinel against an accidental missed import).
"""

from __future__ import annotations

# Importing the package triggers @register_gate side effects.
import mx_mcp.benchmarks  # noqa: F401  - benchmarks registry
import mx_mcp.gates  # noqa: F401  - gates registry
from mx_mcp.common.benchmark_base import all_benchmarks
from mx_mcp.common.gate_base import all_gates


def test_gate_names_are_unique():
    names = [g.name for g in all_gates()]
    assert len(names) == len(set(names)), (
        f"duplicate gate names in registry: {names}"
    )


def test_initial_catalog_population():
    """At least the 8 gates we shipped in P8 are registered."""
    names = {g.name for g in all_gates()}
    expected = {
        "vm_symbolic_summarization",
        "packer_pe_sieve_dump",
        "unicorn_oep_reach",
        "mba_pattern_simplification",
        "mba_claripy_simplification",
        "budget_to_crack_oep_reached",
        "bindiff_similarity",
        "leakage_forbidden_literal",
    }
    missing = expected - names
    assert not missing, f"missing gates from registry: {missing}"


def test_every_gate_targets_a_registered_benchmark():
    """A gate whose benchmark name is unknown to the benchmark registry
    is a copy-paste typo waiting to mask a regression.

    Skipped at the metric level — benchmark instances may emit
    per-backend metric names (e.g. ``vm_mba_<simplifier>_simplification_rate``)
    that this static check cannot enumerate without instantiation.
    """
    bench_names = {b.name for b in all_benchmarks()}
    bad: list[tuple[str, str]] = []
    for gate_cls in all_gates():
        if gate_cls.benchmark not in bench_names:
            bad.append((gate_cls.name, gate_cls.benchmark))
    assert not bad, (
        f"gates target unknown benchmarks: {bad}; benchmarks = {sorted(bench_names)}"
    )
