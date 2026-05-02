# MxProtector MCP — Defense Measurement Suite

Multi-backend MCP server. Backends organised by mode: dynamic /
emulation / symbolic / static / deobfuscation / unpacking /
anti-analysis / diffing.

Post-MVP: [`FUTURE.md`](FUTURE.md). Install: [`mcp/README.md`](mcp/README.md).

## Principles
- SOLID/OCP: new backend/benchmark = new file + decorator, no edits elsewhere.
- ~300 LOC cap per file. One-responsibility-per-file.
- No global state. `ProtectionContext` (C++) / `Session` (Python).
- Fail-closed: crash/timeout = worst-case metric. Silent PASS forbidden.
- Corpus-based: distributions over ≥10 samples; gates use p90.
- `--trace-hints` off by default, never in production (see `STABILITY.md`).

## Agent façade (top-level MCP tools)

| Tool | Purpose |
|---|---|
| `measure_defense` | Run benchmarks on protected PE → `{category: {metric: value}}`. |
| `diff_defense_baseline` | Compare to baseline. Verdicts: improved / regressed / unchanged / gate_failed. |
| `record_baseline` | Snapshot metrics to `baselines/data/`. |
| `list_sections` | Static read of `.mxtrace.json` sidecar. |
| `verify_protection_invariants` | Run invariants (`oep_is_stub`, `packer_decrypted`, …). |
| `protect_and_trace` | Build one PE + Frida trace (diagnostic). |

## Taxonomy (MVP)

```
mcp/
├── pyproject.toml, README.md
├── baselines/data/*.json
├── fixtures/corpus/
├── tests/
└── src/mx_mcp/
    ├── __main__.py, server.py
    ├── common/           tool_base, invariant_base, benchmark_base,
    │                     sidecar, events, pe_reader, corpus, tiers,
    │                     baselines, logging_setup
    ├── dynamic/frida/    session, probes/, tools/
    ├── emulation/unicorn/  OEP-reach, VM handler replay
    ├── symbolic/angr/    VM summarizer, budget-to-crack
    ├── static/
    │   ├── sidecar_tools/  list_sections
    │   └── ida/            headless idat.exe + scripts/
    ├── deobfuscation/mba/  msynth, simba, constant_recovery
    ├── unpacking/        pe_sieve, unicorn_unpack, public/unipacker
    ├── anti_analysis/    coverage.py + envs/
    ├── diffing/bindiff/  two-build similarity
    ├── benchmarks/       cff, vm, packer, mutation, anti_analysis,
    │                     diffing, budget_to_crack
    ├── invariants/       oep_is_stub, packer_decrypted
    ├── reporting/        text_formatter + charts/ (matplotlib)
    └── tools/            measure_defense, diff_defense_baseline,
                          record_baseline, verify_protection_invariants
```

Empty slots (see `FUTURE.md`): `dynamic/{dynamorio,pin,qemu}`,
`emulation/qiling`, `symbolic/{triton,miasm,z3}`, `static/{ghidra,binja}`,
`deobfuscation/{cff_deobf,devirt,qsynth}`, `unpacking/public/{vmattack,unlicense}`,
`fuzzing/`.

## Benchmarks (MVP)

`↑` higher-better, `↓` lower-better, `false-best` bool (false good).

### CFF
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| d810 state recovery rate (p90) | ↓ | IDA+d810 | FAIL ≥50% |
| Dispatcher transition entropy | ↑ | sidecar | warn Δ≥0.2 bit |
| HexRays microcode blocks/goto/cyclomatic | ↑ | IDA | warn ≥15% regression |
| Back-edge / irreducible-region ratio | ↑ | IDA | warn |

CFF population: single region `sections["cff"]`, not per-function. Dispatchers reachable only via indirect jumps → IDA auto-analysis finds zero. Hand IDA an explicit range via `MX_MCP_IDA_REGIONS` + `ida_hexrays.gen_microcode(..., MMAT_GLBOPT3)`. Requires plaintext bytes → build with `--no-packer`.

### VM
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| angr handler-summarization rate | ↓ | angr | FAIL ≥70% |
| Handler opcode histogram entropy | ↑ | sidecar | min threshold |
| Bytecode entropy | ↑ | sidecar + raw dump | min threshold |
| `|bytecode|/|original_code|` ratio | – | sidecar | baseline diff |

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
| OEP discoverable via TLS/early | false-best | IDA | — |

### Mutation / MBA
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| msynth simplification rate | ↓ | msynth | FAIL ≥80% |
| SiMBA simplification rate | ↓ | SiMBA | FAIL ≥80% |
| Constant recoverability | false-best | const-prop + msynth | FAIL on recover |
| IDA pseudocode size delta vs unprotected | ↑ | IDA | min ratio |

### Anti-analysis (cross-cutting)
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| Detection coverage {x64dbg, Frida, Unicorn, pafish, al-khaser} | ↑ | `anti_analysis/coverage` | FAIL < threshold |

### Diffing-resistance
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| BinDiff similarity between two seeded builds | ↓ | BinDiff | FAIL ≥70% |

### Budget-to-crack
| Metric | Dir | Backend | Gate |
|---|---|---|---|
| angr symbolic steps to reach OEP | ↑ | angr | warn on regression |

## Visualisation

Per-metric `MetricScale{weak_value → 0.0, strong_value → 1.0}`. Direction-agnostic linear formula. For `LOWER_BETTER`: `weak=1.0, strong=0.0`.

`reporting/`:
| Module | Produces | Deps |
|---|---|---|
| `text_formatter.py` | measurement/diff summary | stdlib |
| `charts/measurement_chart.py` | per-metric bar PNG | matplotlib |
| `charts/diff_chart.py` | delta bars PNG vs baseline | matplotlib |
| `render_or_skip.py` | fail-closed PNG helper | stdlib |

`measure_defense` / `diff_defense_baseline` accept `output_png`. Missing matplotlib → `png_note` install hint, numeric result unaffected.

## Tier model (MVP)

| Tier | Trigger | Budget | Contents |
|---|---|---|---|
| **fast** | every build | <5 min | sidecar statics, msynth, IDA microcode, pe-sieve, Unicorn OEP-reach, Frida smoke |
| **slow** | pre-PR | <30 min | angr handler-summarization, SiMBA, d810, diffing, anti-analysis coverage, constant-recovery, budget-to-crack |

Gate: **fast FAIL → block commit. slow FAIL → block merge.** `nightly` in `FUTURE.md`.

## Sidecar
Schema v1. Source of truth: `include/mxprotector/analysis/trace_hints.hpp`. Pydantic mirror: `mcp/src/mx_mcp/common/sidecar.py`. `--trace-hints` gated by `config.emit_trace_hints` (test-only, `STABILITY.md`). Additive in v1 → no bump (`extra='ignore'`). Breaking → bump `schema_version`, pydantic rejects old major.

## Corpus
Seed in `mcp/fixtures/corpus/` (not `build_testapp/`). Each entry covers one surface (pure VM, pure CFF, mixed, TLS-heavy, SEH, C++-exception-heavy, DLL). Initial population in **P1**. Metrics: p10/p50/p90. Gates on p90.

## Phases

Migration commit (no behaviour change): relocate `mcp-tools/tracing/` → `mcp/`, rename `mx_tracing` → `mx_mcp`.

One commit per phase. Green gate = pytest + C++ ctest + 15/15 stress on `test_vm_showcase`. Order: signal-per-effort.

- **P5 — Metadata leakage scan.** Regex sweep for protector-internal literals (pass names, debug strings, PDB paths, MSVC linker artefacts, RTTI, `MxProtector`). Surfaces: `no_protector_metadata_leaked` invariant (hard block on forbidden list) + `leakage_surface` benchmark (soft regressions).
- **P6 — VM static + budget-to-crack.** angr symbolic on handlers; score = fraction summarised within budget (wall clock + SMT queries + paths).
- **P7 — MBA resistance.** msynth + SiMBA on handler expressions.
- **P8 — Tier runners + ship-gate.** Fast/slow runners, verdict aggregation.
- **P9 — Emulation Unicorn.** Handler replay + OEP-reach. Scope decision: replay-N-steps vs full engine.
- **P10 — Anti-analysis coverage.** Detection rate across x64dbg, Frida, Unicorn, pafish, al-khaser. Allocate 2–3× budget.

## Risks

| Risk | Mitigation |
|---|---|
| Sidecar ships in production | `--trace-hints` off by default; `trace_hints_leak_test`; `STABILITY.md`. |
| Install burden | Per-backend subpackage + optional `pyproject` extras; self-skip on missing. |
| Overfitting to one MBA solver | Ensemble (msynth ∨ SiMBA); qsynth in `FUTURE.md`. |
| Single-sample gate noise | Corpus p90 everywhere. |
| Backend crash = silent PASS | Fail-closed: timeout/exception → worst-case metric. |
| C++ writer ↔ Python schema drift | `schema_version` + fixture round-trip `tests/test_sidecar.py`. |
