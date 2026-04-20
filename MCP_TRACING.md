# MCP Tracing — Plan

Frida-based runtime tracer MCP for MxProtector. Source-linked labels
emitted by the builder under `--trace-hints` map runtime events back
to CFF states, VM handlers, guard regions, string slots.

## Non-goals
- No static disassembly wrapper (Zydis is in builder).
- No Unicorn fuzzing in MVP.
- No Intel Pin backend.
- Builder has zero dependency on Python / Frida — coupling is sidecar
  schema only.

## Principles
- **SOLID**, especially **OCP**. New behavior = new file.
- One responsibility per file. Hard cap **~300 LOC**.
- No global state. `ProtectionContext` (C++) / `Session` (Python).
- No premature abstractions.

## Green gate (every phase ends here)
1. New unit tests green (`ctest` / `pytest`).
2. **15/15 stress** on `strong`, EXE + DLL (per `CLAUDE.md`).
3. No regression in existing unit tests.
4. One manual e2e smoke against fixture.
5. Commit with scoped message (`feat(mcp-tracing/phaseN): …` /
   `feat(builder/trace-hints): …`).
6. Push.

Fix-forward on the branch if a gate fails.

## Stack (strict)
- **Builder:** C++23 • MSVC • CMake • Zydis • GoogleTest. JSON writer
  hand-rolled.
- **Tracing:** Python 3.11+ • `frida` • `mcp` SDK • `pydantic` v2 •
  `pytest` • `ruff` • `mypy --strict`.
- **Logging:** C++ `ctx.log_fmt`; Python stdlib `logging`, `key=value`.
- **Debug:** `MX_TRACING_DEBUG=1` env toggle.
- **Docs:** Doxygen `@file / @brief / @details` (C++); Google-style
  docstrings (Python).
- **Types:** `[[nodiscard]]`, `std::expected` via `mx::MxResult`;
  `mypy --strict`; pydantic at every boundary.

## Layout

```
mxprotector/
  include/mxprotector/analysis/trace_hints.hpp
  src/builder/analysis/trace_hints.cpp
  src/builder/cli/cli_handler.cpp       # +--trace-hints
  src/builder/main.cpp                  # sidecar writer

.mcp.json                               # Claude Code project-scoped
mcp-tools/
  tracing/
    pyproject.toml
    README.md
    src/mx_tracing/
      __main__.py
      server.py  session.py  sidecar.py  events.py  logging_setup.py
      tools/         # ITool + @register_tool, one file each
      probes/        # static JS: _loader.js + per-kind *.js
      invariants/    # IInvariant + @register_invariant
      metrics/       # IMetric + @register_metric
      baselines/     # IBaselineStore + git_store.py + data/
    fixtures/        # stable PEs covering VM/GUARD/STR/IAT/TLS
    tests/           # pytest on the server itself

MCP_TRACING.md
```

`mcp-tools/` is an umbrella — future `mcp-tools/fuzzing/`,
`mcp-tools/reversing/` slot in without touching `tracing/`.

## Data flow

```
source + SDK markers
  ↓  mxprotector_builder.exe --trace-hints
protected.exe + protected.exe.mxtrace.json
  ↓  protect_and_trace / run_with_probes
frida-spawn → _loader.js → probe.js×N → events.ndjson
  ↓  invariants[].evaluate / metrics[].compute
{ verdicts, metrics }
  ↓  diff_metric vs baselines/data
regression signal
```

## Sidecar schema (v1, frozen Phase 1)

```json
{
  "schema_version": 1,
  "build":    { "input", "output", "level", "timestamp" },
  "sections": { "<role>": { "name", "rva", "size", "characteristics" } },
  "cff":      { "dispatcher_rva", "state_var_rva",
                "states":     [{"id","dispatcher_entry_rva","source_bb_rva","kind"}],
                "predicates": [{"id","rva","kind"}] },
  "vm":       { "dispatcher_rva", "handler_table_rva",
                "handlers":   [{"id","rva","size","opcode"}] },
  "guard":    { "regions":   [{"id","rva","size"}] },
  "strings":  { "slots":     [{"id","desc_rva","plaintext_len"}] },
  "iat":      { "rva", "size" }
}
```

Arrays may be empty. `schema_version` bumps only on breaking changes;
pydantic rejects unknown majors.

## Contracts

**C++ `TraceHints`** (`trace_hints.hpp`): `set_build_info`,
`add_section`, `add_cff_state`, `add_opaque_predicate`,
`add_vm_handler`, `add_guard_region`, `add_string_slot`, `set_iat`,
`to_json`. Emission guarded by `if (ctx.config().emit_trace_hints)`.

**Python ABCs** (all decorator-registered):
- `ITool` — `name`, `input_schema`, `output_schema`,
  `async run(args, session)`.
- `IInvariant` — `name`, `probes`, `evaluate(events, hints) → Verdict`.
- `IMetric` — `name`, `probes`, `compute(events, hints) → MetricResult`.
- `IBaselineStore` — `load(metric, variant)`, `save(...)`.

Adding a new tool / invariant / metric = one new file, zero edits to
existing code.

## Phases

Each phase ends at the **Green gate** above.

### Phase 0 — Scaffold
- `mcp-tools/tracing/` tree; `pyproject.toml`; `__main__.py`.
- Repo-root `.mcp.json`.
- `MCP_TRACING.md` referenced from `ROADMAP.md`.
- Gate: `python -m mx_tracing --version` prints; builder untouched.

### Phase 1 — Sidecar (C++)
- `trace_hints.{hpp,cpp}` with `set_build_info`, `add_section`,
  `to_json`.
- `ProtectionContext::trace_hints()`; `--trace-hints` CLI flag.
- `main.cpp` writes `<output>.mxtrace.json`.
- Unit tests: `trace_hints_test`, `trace_hints_leak_test`.
- Gate: JSON dry-parses against Phase 2 pydantic schema.

### Phase 2 — MCP server + 2 tools
- `ITool` ABC + auto-discovery; pydantic sidecar schema.
- Frida `Session`; `probes/_loader.js`, `api_call.js`, `mem_region.js`.
- Tools: `list_sections`, `protect_and_trace`.
- pytest on fixture.

### Phase 3 — First invariants
- `IInvariant` ABC + registry.
- `packer_decrypted`, `oep_is_stub`.
- `verify_protection_invariants` aggregator.
- Fixture PE.

### Phase 4 — Label emission from passes
- CFF states + predicates; VM handlers; guard regions; string slots;
  IAT range.
- Unit test per pass: labels present iff flag on.
- Gate: 15/15 stress green (collection-only — no runtime change).

### Phase 5 — Remaining invariants
- `iat_wiped`, `tls_fired`, `anti_debug_fired`, `guard_veh_decrypt`.
- One file + one pytest each.

### Phase 6 — Quality metrics
- `IMetric` ABC.
- `measure_cff_quality` — `state_dispatch_histogram`, `top_hot_states`,
  `transition_entropy`, `predicate_bias`, `unused_states`.
- `measure_vm_quality` — `handler_histogram`, `handler_diversity`,
  `vm_vs_native_ratio`.

### Phase 7 — Diff + baselines
- `IBaselineStore` + `git_store`; seed `baselines/data/*.json`.
- `diff_metric` tool (verdicts: `improved / regressed / unchanged`).

### Phase 8 — Polish
- `measure_string_leak`, `measure_decrypt_window`, `compare_trace`,
  `run_with_probes` generic tool.
- README inside `mcp-tools/tracing/`.
- Gate: full pytest + 15/15 stress.

## Risks

| Risk | Mitigation |
|---|---|
| Sidecar ships with production build | Flag off by default; `trace_hints_leak_test`; note in `STABILITY.md`. |
| Frida detected by packer anti-debug | Fixtures built with anti-debug disabled; separate non-Frida canary confirms anti-debug fires on normal builds. |
| Tool surface grows monolithic | OCP ABCs, ~300-LOC cap, decorator registries. |
| Schema drift | `schema_version` + pydantic rejects unknown majors. |
| Python deps poison main project | `mcp-tools/tracing/pyproject.toml` isolated; builder CMake never references it. |
