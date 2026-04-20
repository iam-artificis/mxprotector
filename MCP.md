# MxProtector MCP — Defense Measurement Suite

Multi-backend MCP server measuring MxProtector's protection strength
against state-of-the-art reversing tools. Supersedes the single-backend
tracing MCP: backends are now organised by analysis mode (dynamic /
emulation / symbolic / static / deobfuscation / unpacking /
anti-analysis / diffing) behind a benchmark façade.

Post-MVP backlog: [`FUTURE.md`](FUTURE.md).
Install instructions: [`mcp/README.md`](mcp/README.md).

## Principles

- **SOLID / OCP.** New backend or benchmark = new file + decorator.
  Zero edits to existing code.
- **~300 LOC cap per file.** Nothing is "one-responsibility-per-class";
  it's one-responsibility-per-file.
- **No global state.** `ProtectionContext` (C++) / `Session` (Python).
- **Fail-closed.** Backend crash or timeout = worst-case metric value;
  silent PASS on exception is forbidden.
- **Corpus-based.** Metrics are distributions over ≥10 samples; gates
  use p90 (or worse percentile), not mean.
- **Test-only builder flag.** `--trace-hints` is off by default and
  never ships in production builds (see `STABILITY.md`).

## Agent façade

Top-level MCP tools — the only surface the agent sees. Backends,
scripts, and raw metrics live below.

| Tool | Purpose |
|---|---|
| `measure_defense` | Run benchmarks on a protected PE, return `{category: {metric: value}}`. |
| `diff_defense_baseline` | Compare current metrics to a stored baseline. Verdicts: improved / regressed / unchanged / gate_failed. |
| `record_baseline` | Snapshot current metrics as a named baseline (commits to `baselines/data/`). |
| `list_sections` | Static read of a `.mxtrace.json` sidecar. |
| `verify_protection_invariants` | Run registered invariants (`oep_is_stub`, `packer_decrypted`, …). |
| `protect_and_trace` | Build one PE and trace it under Frida (diagnostic). |

## Taxonomy (MVP)

```
mcp/
├── pyproject.toml, README.md, .gitignore
├── baselines/data/*.json
├── fixtures/corpus/             ← curated mini-binaries (separate from build_testapp/)
├── tests/
└── src/mx_mcp/
    ├── __main__.py, server.py
    ├── common/                  tool_base, invariant_base, benchmark_base,
    │                            sidecar, events, pe_reader, corpus,
    │                            tiers, baselines, logging_setup
    ├── dynamic/frida/           session, probes/, tools/
    ├── emulation/unicorn/       OEP-reach emulator, VM handler replay
    ├── symbolic/angr/           VM summarizer, budget-to-crack
    ├── static/
    │   ├── sidecar_tools/       list_sections
    │   └── ida/                 headless idat.exe + scripts/
    ├── deobfuscation/mba/       msynth, simba, constant_recovery
    ├── unpacking/               pe_sieve, unicorn_unpack, public/unipacker
    ├── anti_analysis/           coverage.py + envs/
    ├── diffing/bindiff/         two-build similarity
    ├── benchmarks/              cff, vm, packer, mutation,
    │                            anti_analysis, diffing, budget_to_crack
    ├── invariants/              oep_is_stub, packer_decrypted
    ├── reporting/               text_formatter + charts/ (matplotlib)
    └── tools/                   measure_defense, diff_defense_baseline,
                                 record_baseline, verify_protection_invariants
```

Empty slots kept in sync with `FUTURE.md`: `dynamic/{dynamorio,pin,qemu}`,
`emulation/qiling`, `symbolic/{triton,miasm,z3}`, `static/{ghidra,binja}`,
`deobfuscation/{cff_deobf,devirt,qsynth}`, `unpacking/public/{vmattack,unlicense}`,
`fuzzing/`.

## Benchmarks (MVP)

Direction: `↑` = higher-is-better, `↓` = lower-is-better, `false-best` = bool where false is good.

### CFF

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| d810 state recovery rate (per-fn p90) | ↓ | IDA+d810 | FAIL ≥50% |
| Dispatcher transition entropy | ↑ | sidecar | warn Δ≥0.2 bit |
| HexRays microcode blocks/goto/cyclomatic (section-aggregate) | ↑ | IDA | warn on ≥15% regression |
| Back-edge / irreducible-region ratio | ↑ | IDA | warn |

**Population contract (implementation note).** The CFF benchmark
measures ``sections["cff"]`` as a *single region* — not per-function.
The CFF pass emits each source function's dispatcher + state handlers
into that section; IDA's auto-analysis does not create functions at
the dispatcher entries (they're reachable only through indirect
jumps), so any "iterate IDA functions" population filter returns
zero matches. The benchmark therefore hands IDA one explicit range
via ``MX_MCP_IDA_REGIONS`` and runs
``ida_hexrays.gen_microcode(..., MMAT_GLBOPT3)`` directly on the
bytes — which requires the on-disk bytes to be *plaintext*, so the
benchmark builds with ``--no-packer`` (packer encrypts the section
at build time; it decrypts only at runtime). Packer quality gets its
own benchmark later.

### VM

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| angr handler-summarization rate | ↓ | angr | FAIL ≥70% |
| Handler opcode histogram entropy | ↑ | sidecar | min threshold |
| Bytecode entropy | ↑ | sidecar + raw dump | min threshold |
| `|bytecode| / |original_code|` ratio | – | sidecar | baseline diff |

### Packer

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| pe-sieve dump success | false-best | pe-sieve | FAIL on clean dump |
| Unicorn OEP-reach | false-best | Unicorn | FAIL on reach |
| unipacker success | false-best | unipacker | FAIL on success |
| Anti-debug probe hits | ↑ | Frida | FAIL < N |
| Decryption window (ms) | ↓ | Frida | warn +20% |
| Decrypted-at-once coverage `%.text` | ↓ | Frida | FAIL ≥80% |
| IAT dynamic-resolve count | ↑ | Frida | — |
| OEP discoverable via TLS / early | false-best | IDA | — |

### Mutation / MBA

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| msynth simplification rate | ↓ | msynth | FAIL ≥80% |
| SiMBA simplification rate | ↓ | SiMBA | FAIL ≥80% |
| Constant recoverability | false-best | const-prop + msynth | FAIL on recover |
| IDA pseudocode size delta vs. unprotected | ↑ | IDA | min ratio |

### Anti-analysis (cross-cutting)

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| Detection coverage under {x64dbg, Frida, Unicorn, pafish-env, al-khaser-env} | ↑ | `anti_analysis/coverage` | FAIL < threshold |

### Diffing-resistance

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| BinDiff similarity between two seeded builds | ↓ | BinDiff | FAIL ≥70% |

### Budget-to-crack (cross-cutting KPI)

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| angr symbolic steps to reach OEP | ↑ | angr | warn on regression |

## Visualisation

Each per-metric result carries an optional ``MetricScale`` declared by
the benchmark:

```
weak_value  → 0.0   (defence is ineffective)
strong_value → 1.0  (defence is working well)
```

The scale is direction-agnostic — the same linear formula handles
``HIGHER_BETTER`` / ``LOWER_BETTER`` / ``FALSE_BEST`` as long as the
benchmark sets ``weak``/``strong`` consistently (e.g. for
``LOWER_BETTER`` use ``weak=1.0``, ``strong=0.0``).

The ``reporting/`` subpackage turns runs into text + PNG:

| Module | Produces | Depends on |
|---|---|---|
| `reporting/text_formatter.py` | Human-readable measurement / diff summary | stdlib only |
| `reporting/charts/measurement_chart.py` | Normalised per-metric bar PNG for a measurement | matplotlib |
| `reporting/charts/diff_chart.py` | Coloured delta bars PNG vs a baseline | matplotlib |
| `reporting/render_or_skip.py` | Fail-closed helper tools use to attach a PNG | stdlib only |

Both `measure_defense` and `diff_defense_baseline` accept an
`output_png` argument. When set and the `[viz]` extra is installed,
the tool writes the chart at that path and returns it alongside the
numeric output. When matplotlib is missing, `png_note` carries the
install hint and the numeric result is unaffected.

Install the chart backend:

```bash
cd mcp && py -3 -m pip install -e ".[viz]"
```

## Tier model (MVP — two tiers)

| Tier | Trigger | Budget | Contents |
|---|---|---|---|
| **fast** | every build | <5 min | sidecar statics, msynth, IDA microcode, pe-sieve, Unicorn OEP-reach, Frida smoke |
| **slow** | pre-PR review | <30 min | angr handler-summarization, SiMBA ensemble, d810, diffing-resistance, anti-analysis coverage, constant-recovery, budget-to-crack |

Gate policy: **fast FAIL → block commit. slow FAIL → block merge.**

A third `nightly` tier (Z3 equivalence, full 100+ corpus, public
unpackers) lives in [`FUTURE.md`](FUTURE.md).

## Sidecar contract

Schema v1. Source of truth: `include/mxprotector/analysis/trace_hints.hpp`.
Pydantic mirror: `mcp/src/mx_mcp/common/sidecar.py`. `--trace-hints`
CLI flag (gated by `config.emit_trace_hints`) is test-only per
`STABILITY.md`.

Additive changes within v1 require no bump (pydantic `extra='ignore'`).
Breaking changes bump `schema_version`; pydantic then rejects the old
major with a named error so the two sides do not drift.

## Corpus

MVP seed: curated mini-binaries in `mcp/fixtures/corpus/` (separate
from `build_testapp/` — that dir is for functional stress testing, not
for benchmark input population). Each entry covers a specific
protection surface (pure VM, pure CFF, mixed, TLS-heavy, SEH,
C++-exception-heavy, DLL variant). Initial population in **P1**.

Metrics are computed over all corpus samples and reported as
p10 / p50 / p90. Gates use p90 so a single broken hot-function in a
build cannot hide behind the mean.

## Phases

**Migration commit** (no behavioural change): relocate
`mcp-tools/tracing/` → `mcp/`, rename namespace `mx_tracing` →
`mx_mcp`, reorganise into taxonomy. Green gate: existing pytest
discovers + passes after rebuild of the builder.

Then one commit per phase, each ending at the green gate (pytest +
C++ ctest + 15/15 stress on `test_vm_showcase`):

- **P1** — Benchmark infra (`IBenchmark`, `corpus`, `tiers`, `baselines`,
  three top-level MCP tools). Populate `fixtures/corpus/` with seed.
- **P2** — Static IDA headless (runner + CFF microcode + back-edge
  ratio → CFF benchmark).
- **P3** — Emulation Unicorn (handler replay + OEP-reach → Packer
  benchmark partial).
- **P4** — Symbolic angr (VM handler summarizer + budget-to-crack →
  VM benchmark partial + cross-cutting KPI).
- **P5** — Deobf MBA (msynth + SiMBA ensemble + constant-recovery →
  Mutation benchmark).
- **P6** — Unpacking (pe-sieve + unipacker → Packer benchmark
  complete).
- **P7** — Anti-analysis coverage (detection coverage across
  adversarial envs).
- **P8** — Diffing-resistance (BinDiff between seeded builds).
- **P9** — Tier runners + ship-gate wiring (fast / slow runners,
  verdict aggregation).

## Risks

| Risk | Mitigation |
|---|---|
| Sidecar ships in production | `--trace-hints` off by default; `trace_hints_leak_test`; `STABILITY.md`. |
| Install burden of backends | Each backend in its own subpackage with optional `pyproject` extras. Tools self-skip with a readable message when their backend is absent. |
| Overfitting to one MBA solver | Ensemble gate (msynth ∨ SiMBA); qsynth peer in `FUTURE.md`. |
| Statistical noise on single-sample gates | Corpus p90 everywhere; gate thresholds set with noise band in mind. |
| Backend crash = silent PASS | Fail-closed: timeout / exception → worst-case metric value. |
| Drift between C++ writer and Python schema | `schema_version` + fixture round-trip test in `tests/test_sidecar.py`. |
