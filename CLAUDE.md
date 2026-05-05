# MxProtector — Agent Working Notes

**Tech:** C++23. **Rule:** Test everything. Commit + push after every step.

## Cross-platform stance

* **Host:** the builder runs on Windows and Linux. Don't hard-code
  `\\` separators (use `std::filesystem::path` + forward slashes),
  Win32-only APIs, or MSVC-only intrinsics. CI runs on both.
* **Targets:** today only Windows PE x64 is fully wired. ELF + ARM64
  are roadmap. Every new pass must (1) gate via
  `ctx.target().is_...()` (e.g. `is_windows_pe_x64()`) and bail out
  cleanly when the predicate fails — never crash on non-PE / non-x64
  inputs; (2) keep architecture-specific code (encoders, emitters,
  rewriters, VM handlers) under an arch directory (`x64/`, future
  `arm64/`) behind an `arch::IXxxBackend` interface so adding ARM64
  is a new sibling, not edits to existing files. PE/ELF differences
  belong behind `pe::` / future `elf::` containers.

## Build & Test
```
"C:/.../Visual Studio/.../CMake/bin/cmake.exe" --build build --config Release --target mxprotector_builder
build/src/builder/Release/mxprotector_builder.exe -i test_vm_showcase.exe -o t.exe -l strong
# Stress (15 runs):
for i in $(seq 1 15); do ../build/.../mxprotector_builder.exe -i in.exe -o t.exe -l strong >/dev/null; ./t.exe || echo "FAIL"; done
```

## Pipeline
1. `MutationPass` (100): Substitutions, junk, splitting, register reassignment. Optional MBA rewriting via `enable_mba_substitution` (defeats SMT/symbolic; OF/AF differ from original — opt-in only).
2. `ObfuscationPass` (200): Opaque predicates, MBA, constant unfolding.
3. `VirtualizationPass` (300): Lifts `MX_VM_BEGIN/END` to VM bytecode.
4. `GuardPass` (350): Relocates `MX_GUARD_BEGIN/END` to `.mxguard`, VEH dispatch, VM-lifted decrypt.
5. `CfgFlatteningPass` (400): Dispatcher, MBA transitions.
6. `StringProtectionPass` (500): Encrypts string literals, VM-lifted decryptor stub.
7. `PackerPass` (800): Multi-section RC4, inline stub, anti-debug, IAT wipe, TLS callbacks.

## Architecture
- Passes implement `IProtectionPass`. No global state.
- `TargetInfo{os, container, arch}` — passes guard via `ctx.target().is_...()`.
- Section names: never hardcode, use `ctx.section_names()` (random per build).
- Extending VM: add handler variants in `src/builder/protection/vm/x64/`, update enum, increment `kCount`.

## Do NOT
- Revive `EncryptionPass` or `stub_main` loader — packer owns encryption.
- Hardcode `is_applicable()` without target/arch checks.
- Commit dead/unused code.

## MCP result storage layout

All measurement artefacts live under `mcp/reports/` (git-ignored):
```
mcp/reports/
├── charts/        — rendered PNGs (one per run / one per phase)
├── runs/          — driver scripts + per-run logs
└── snapshots/     — auto-captured measurement snapshots (was
                     mcp/snapshots/ before consolidation)
```
Drivers compute `WORKSPACE = Path(__file__).resolve().parents[3]`
and write into `mcp/reports/charts/`. `measure_defense` /
`compare_snapshots` default `snapshots_root` to
`mcp/reports/snapshots/`.

## Strict code rules (HARD REQUIREMENTS)

These rules are **non-negotiable** for every change. A patch that
violates any of them must not be committed.

1. **SOLID, OCP-first.** New behaviour = new file + decorator/registry,
   never edits to existing pass/benchmark/tool registries. One
   responsibility per class, one class per concern.
2. **Language standard.** C++ is **C++20 minimum** (current project
   tree compiles as C++23 — keep it; never downgrade). Python is
   **3.10+** with `from __future__ import annotations`.
3. **No monolithic files.** Hard cap **~300 LOC per file**, **~50 LOC
   per function**. Split by responsibility — never by line count
   alone. If a pass / benchmark / tool grows past the cap, factor
   helpers into siblings under the same package.
4. **Docstrings everywhere.** Every public class/function/free
   function carries a docstring (or doxygen `///` for C++). Lead
   with what + why; cover preconditions, raised errors, and any
   non-obvious invariant. Headers explain the *module* in 5+ lines.
5. **Tests, mandatory.** Every new module ships with unit tests in
   `mcp/tests/` (Python) or `tests/` (C++/ctest). Mock external
   backends (angr, IDA, Frida, builder subprocess); fail-closed
   semantics tested explicitly. Bug fix → regression test first,
   then fix.
6. **Logs at every meaningful boundary.** `logging.getLogger(__name__)`
   in Python, `MX_LOG_*` macros in C++. INFO for one-line per-entry
   summaries; DEBUG for inner-loop detail; ERROR for fail-closed
   exits. Never `print` / `std::cout` in shipped code.
7. **No global state.** `ProtectionContext` (C++) / `Session` +
   constructor injection (Python). Test seams via constructor args,
   never module-level monkeypatching of production code paths.
8. **Fail-closed, never silent.** Backend crash / timeout / missing
   tool → error surfaced + worst-case metric. A `try/except: pass`
   anywhere is a code-review blocker.
9. **No dead / commented-out code.** No `// removed`, no `_unused`
   shims, no backwards-compatibility leftovers. Delete it; `git`
   keeps the history.
10. **Match existing style exactly.** Pre-existing benchmarks /
    passes are the reference: register-decorator pattern, file
    headers, `_METRIC_DEFS` tables, helper sections. Do not invent
    parallel idioms.