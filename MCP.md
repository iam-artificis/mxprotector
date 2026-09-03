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

Registered in `mx_mcp/tools/__init__.py`; backend-specific tools live under each backend's own `tools/` subpackage (e.g. `dynamic/frida/tools/protect_and_trace`).

| Tool | Purpose |
|---|---|
| `measure_defense` | Run every registered benchmark on a protected PE → `{category: {metric: value}}` + evidence + errors. |
| `record_baseline` | Snapshot current metrics to `baselines/data/` for future diffs. |
| `diff_defense_baseline` | Compare current run against a stored baseline. Verdicts: improved / regressed / unchanged / gate_failed. |
| `compare_snapshots` | Compare two auto-captured measurement snapshots under `mcp/reports/snapshots/`. |
| `verify_protection_invariants` | Run every registered invariant (`no_protector_metadata_leaked`, `oep_is_stub`, `packer_decrypted`). Hard block on failure. |
| `run_tier` | Execute a tier (`fast` / `slow`), run its benchmarks, evaluate every gate, return a single `gate_passed` bool. |

## Taxonomy

```
mcp/
├── pyproject.toml, README.md
├── baselines/data/*.json
├── fixtures/corpus/
├── reports/{charts,runs,snapshots}/     (git-ignored)
├── tests/
└── src/mx_mcp/
    ├── __main__.py, server.py
    ├── common/              tool_base, invariant_base, benchmark_base,
    │                        gate_base, builder, sidecar, events,
    │                        pe_reader, corpus, tiers, baseline(s),
    │                        snapshots, leakage_scan, ida_cfg_baseline,
    │                        ratio, git_info, logging_setup
    ├── anti_analysis/       coverage.py, detector_base,
    │   │                    _static_evidence
    │   └── detectors/       x64dbg, frida, unicorn, pafish, al_khaser
    ├── benchmarks/          one file per benchmark (11 today, see below)
    ├── deobfuscation/mba/   extractor, expression, simplifier,
    │                        simplifier_pattern, pattern_engine,
    │                        pattern_rules
    ├── diffing/bindiff/     binexport_runner, bindiff_runner, report
    ├── dynamic/frida/       session, probes/, tools/
    ├── emulation/unicorn/   loader, runner, budget, _drivers
    ├── gates/               one file per gate, wired to _thresholds
    ├── invariants/          no_protector_metadata_leaked,
    │                        oep_is_stub, packer_decrypted
    ├── reporting/           text_formatter, render_or_skip,
    │   └── charts/          measurement, diff, comparison (matplotlib)
    ├── shipgate/            evaluator, runner (drives `run_tier`)
    ├── static/
    │   ├── sidecar_tools/   list_sections
    │   └── ida/             headless idat.exe + scripts/
    ├── symbolic/angr/       runner, oep_reach, budget
    ├── tools/               compare_snapshots, diff_defense_baseline,
    │                        measure_defense, record_baseline,
    │                        run_tier, verify_protection_invariants
    └── unpacking/pe_sieve/  runner, process_controller, report
```

Empty slots (see `FUTURE.md`): `dynamic/{dynamorio,pin,qemu}`,
`emulation/qiling`, `symbolic/{triton,miasm,z3}`, `static/{ghidra,binja}`,
`deobfuscation/{cff_deobf,devirt,qsynth}`, `unpacking/public/{vmattack,unlicense}`,
`fuzzing/`.

## Benchmarks

`↑` higher-better, `↓` lower-better, `false-best` bool (false good). Each benchmark ships in `mcp/src/mx_mcp/benchmarks/<name>.py` and self-registers.

### CFF — `cff_benchmark`
Filtered microcode amplification + coverage. Populates `sections["cff"]` region via IDA (`MX_MCP_IDA_REGIONS`, `MMAT_GLBOPT3`), filtered by sidecar `protected_functions[kind=="cff"]`. Requires plaintext bytes → build with `--no-packer`.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `mc_blocks_amplification` | ↑ | IDA | warn on regression |
| `mc_cyclomatic_amplification` | ↑ | IDA | warn |
| `mc_goto_amplification` | ↑ | IDA | warn |
| `mc_backedges_amplification` | ↑ | IDA | warn |
| `mc_cff_coverage` | ↑ | IDA | warn |

### VM static — `vm_benchmark`
Filtered footprint + coverage + entropy over VM-tagged corpus entries. Reads `.vm` section bytes, divides by baseline `functions_total_bytes` of the VM'd source functions.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| Bytecode entropy | ↑ | sidecar + raw dump | min threshold |
| `.vm`-footprint / source-function-bytes ratio | ↑ | sidecar + PE | baseline diff |
| Coverage across `.text` | ↑ | sidecar | baseline diff |

### VM symbolic — `vm_symbolic_benchmark`
angr handler-summarization + per-handler symbolic-cost, both under wall/step/path budget. Pair with `vm_benchmark` (static) and `vm_mba_benchmark` (algebraic).

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `vm_handler_summarization_rate` | ↓ | angr | FAIL ≥ threshold |
| `vm_symbolic_cost_mean_steps` | ↑ | angr | warn on regression |

### VM handler replay — `vm_handler_replay_benchmark`
Unicorn-driven per-handler emulation, single metric by design (tail dispatch always completes, so a completion-rate row would be constant).

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `vm_handler_unicorn_mean_instructions` | ↑ | Unicorn | warn |

### VM MBA — `vm_mba_benchmark`
Extractor + simplifier ensemble (Claripy, pattern) over angr-extracted handler output ASTs. One `simplification_rate` row per registered backend that ran.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `vm_mba_expression_mean_ast_nodes` | ↑ | extractor | warn |
| `vm_mba_claripy_simplification_rate` | ↓ | Claripy | FAIL ≥ threshold |
| `vm_mba_pattern_simplification_rate` | ↓ | pattern | FAIL ≥ threshold |

### Packer — `packer_benchmark`
Two scored metrics + one unscored canary (`implanted_pe`) surfaced as `CANARY`-prefixed benchmark errors, not scores.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `pesieve_dumped_modules` | ↓ | pe-sieve | FAIL on clean dump |
| `pesieve_fingerprint_count` | ↓ | pe-sieve | warn |

### Budget-to-crack — `budget_to_crack_benchmark`
End-to-end stub resistance: how many angr steps to symbolically reach the unprotected binary's OEP under budget. Pre-protected entries rejected (need ground-truth EP RVA).

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `budget_to_crack_steps_to_oep` | ↑ | angr | warn |
| `budget_to_crack_oep_reached` | false-best | angr | FAIL on reach |

### Unicorn OEP-reach — `unicorn_oep_reach_benchmark`
Fast-tier dynamic-emulation sibling of `budget_to_crack_benchmark`. Loads the protected PE, emulates from the packer stub, watches for PC at the unprotected OEP. Crash = defence signal.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `unicorn_oep_reached` | false-best | Unicorn | FAIL on reach |
| `unicorn_instructions_to_oep` | ↓ | Unicorn | warn |

### Leakage — `leakage_benchmark`
Soft regression surface complementary to the hard-block `NoProtectorMetadataLeakedInvariant`. All three metrics are `LOWER_BETTER`.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `leaked_forbidden_literal_count` | ↓ | `leakage_scan` | FAIL ≥ 1 |
| `leaked_pdb_path_count` | ↓ | `leakage_scan` | warn |
| `leaked_rich_header_present` | ↓ | `leakage_scan` | warn |

### Anti-analysis coverage — `anti_analysis_benchmark`
Walks the `IDetector` registry (x64dbg, Frida, Unicorn, pafish, al-khaser), collapses per-detector outcomes into a `DetectionCoverage`.

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `anti_analysis_coverage_rate` | ↑ | `anti_analysis/detectors` | FAIL < 0.4 |

### Diffing-resistance — `bindiff_benchmark`
Two same-source builds → IDA + BinExport → `bindiff.exe`. Pre-protected entries rejected (no source to re-seed).

| Metric | Dir | Backend | Gate |
|---|---|---|---|
| `bindiff_similarity` | ↓ | BinDiff | FAIL ≥ threshold |
| `bindiff_function_match_ratio` | ↓ | BinDiff | warn |

## Visualisation

Per-metric `MetricScale{weak_value → 0.0, strong_value → 1.0}`. Direction-agnostic linear formula. For `LOWER_BETTER`: `weak > strong`; for `FALSE_BEST`: `weak=1.0, strong=0.0`.

`reporting/`:
| Module | Produces | Deps |
|---|---|---|
| `text_formatter.py` | measurement / diff summary text | stdlib |
| `charts/measurement_chart.py` | per-metric bar PNG | matplotlib |
| `charts/diff_chart.py` | delta bars PNG vs baseline | matplotlib |
| `charts/comparison_chart.py` | snapshot-vs-snapshot bars PNG | matplotlib |
| `render_or_skip.py` | fail-closed PNG helper | stdlib |

`measure_defense` / `diff_defense_baseline` / `compare_snapshots` accept `output_png`. Missing matplotlib → `png_note` install hint, numeric result unaffected.

## Tier model

Wired via `mx_mcp/shipgate/` (`TierRunner` + `GateEvaluator`) and the `IGate` implementations in `mx_mcp/gates/`. `run_tier` returns a single `gate_passed` bool.

| Tier | Trigger | Budget | Contents |
|---|---|---|---|
| **fast** | every build | <5 min | sidecar statics, `vm_benchmark`, `cff_benchmark`, `packer_benchmark`, `unicorn_oep_reach_benchmark`, `leakage_benchmark`, Frida smoke |
| **slow** | pre-PR | <30 min | `vm_symbolic_benchmark`, `vm_handler_replay_benchmark`, `vm_mba_benchmark`, `budget_to_crack_benchmark`, `bindiff_benchmark`, `anti_analysis_benchmark` |

Registered gates (`mx_mcp/gates/`): `anti_analysis_coverage`, `bindiff_similarity`, `budget_to_crack_oep`, `leakage_forbidden_literal`, `mba_claripy_simplification`, `mba_pattern_simplification`, `packer_pe_sieve`, `unicorn_oep_reach`, `vm_symbolic_summarization`. Thresholds centralised in `_thresholds.py`.

Gate policy: **fast FAIL → block commit. slow FAIL → block merge.** `nightly` in `FUTURE.md`.

## Sidecar
Schema v1. Source of truth: `include/mxprotector/analysis/trace_hints.hpp`. Pydantic mirror: `mcp/src/mx_mcp/common/sidecar.py`. `--trace-hints` gated by `config.emit_trace_hints` (test-only, `STABILITY.md`). Additive in v1 → no bump (`extra='ignore'`). Breaking → bump `schema_version`, pydantic rejects old major.

## Corpus
Seed in `mcp/fixtures/corpus/` (not `build_testapp/`). Each entry covers one surface (pure VM, pure CFF, mixed, TLS-heavy, SEH, C++-exception-heavy, DLL). Metrics: p10/p50/p90. Gates on p90.

## Phase log (landed)

The original migration plan ran one commit per phase against a green gate of `pytest + C++ ctest + 15/15 stress on test_vm_showcase`. All MVP phases are landed; this log is the canonical pointer for code comments that cite a phase identifier.

| Phase | What landed |
|---|---|
| P1 / P2 / P4 | Migration (`mcp-tools/tracing/` → `mcp/`, rename `mx_tracing` → `mx_mcp`), sidecar schema v1, corpus loader, `measure_defense` / `record_baseline` / `diff_defense_baseline` tool surface, charts, snapshot store. |
| P3 (partial) | pe-sieve runner + `packer_benchmark` + `packer_decrypted` invariant. Full Frida anti-debug instrumentation deferred — see `FUTURE.md`. |
| P5 | Metadata-leakage: `no_protector_metadata_leaked` invariant (hard block on forbidden list) + `leakage_benchmark` (PDB / Rich-header / forbidden-literal). |
| P6 | VM symbolic + budget-to-crack: `vm_symbolic_benchmark` (handler summarisation rate + mean symbolic cost) and `budget_to_crack_benchmark` (steps to OEP + reached-bool), both via angr under wall / step / path budget. |
| P7 | MBA resistance: Claripy + pattern simplifier ensemble over angr-extracted handler output ASTs, surfaced as `vm_mba_benchmark`. |
| P8 | Tier runners + ship-gate: `IGate` registry (9 gates), `GateEvaluator` + `TierRunner` aggregation in `shipgate/`, `run_tier` MCP tool returning a single `gate_passed` bool. |
| P9 | Emulation Unicorn: PE → Unicorn loader (no PEB/TEB/ntdll synthesis — crashes on missing infra are the defence signal), `unicorn_oep_reach_benchmark` + `vm_handler_replay_benchmark`. |
| P10 | Anti-analysis coverage: `IDetector` registry (`anti_analysis/detectors/`) + 5 detectors (x64dbg, Frida, Unicorn, pafish, al-khaser), `anti_analysis_benchmark` + slow-tier gate. |

## Risks

| Risk | Mitigation |
|---|---|
| Sidecar ships in production | `--trace-hints` off by default; `trace_hints_leak_test`; `STABILITY.md`. |
| Install burden | Per-backend subpackage + optional `pyproject` extras; self-skip on missing. |
| Overfitting to one MBA solver | Ensemble (Claripy ∨ pattern); qsynth / SiMBA in `FUTURE.md`. |
| Single-sample gate noise | Corpus p90 everywhere. |
| Backend crash = silent PASS | Fail-closed: timeout/exception → worst-case metric. |
| C++ writer ↔ Python schema drift | `schema_version` + fixture round-trip `tests/test_sidecar.py`. |
