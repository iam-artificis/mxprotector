# Contributing to mxprotector

Thanks for your interest in improving MxProtector. This guide covers
the environment, the workflow, and the code rules every change is
held to. Read it before opening a pull request.

## Environment

- CMake >= 3.20
- A C++23 compiler: MSVC 2022, GCC 13+, or Clang 16+
- Python 3.11+ for the measurement suite in `mcp/`
- Run `git submodule update --init --recursive` before configuring
  (pulls Zydis and other vendored deps)

The builder is developed on Windows and Linux; CI runs on both. Do
not hard-code `\\` separators (use `std::filesystem::path` with
forward slashes), Win32-only APIs, or MSVC-only intrinsics.

## Build and test

Configure once, then build and test:

```bash
cmake -S . -B build -DMXPROTECTOR_BUILD_TESTS=ON
cmake --build build --config Release
ctest --test-dir build --output-on-failure
cd mcp && pip install -e '.[dev]' && pytest
```

The full C++ suite (`ctest`) plus the Python suite (`pytest`) must be
green before you open a PR. If your change touches the protection
pipeline, run the strong-level stress loop from the README against a
representative PE and confirm 15/15 runs succeed.

## Code rules (non-negotiable)

These rules are hard requirements. A patch that violates any of them
will not be merged.

1. **SOLID, open/closed first.** New behavior is a new file plus a
   decorator or registry entry — never edits to existing pass,
   benchmark, or tool registries. One responsibility per class, one
   class per concern.
2. **Language standard.** C++ is **C++20 minimum**; the current tree
   compiles as C++23 and stays that way — never downgrade. Python is
   **3.10+** with `from __future__ import annotations` at the top of
   every module.
3. **No monolithic files.** Hard cap of **~300 LOC per file** and
   **~50 LOC per function**. Split by responsibility, not by line
   count alone. When a pass, benchmark, or tool grows past the cap,
   factor helpers into siblings under the same package.
4. **Docstrings on every public surface.** Doxygen `///` for C++,
   PEP-257 docstrings for Python. Lead with what and why; cover
   preconditions, raised errors, and any non-obvious invariant.
   Module headers explain the module in five or more lines.
5. **Tests are mandatory.** Every new module ships with unit tests
   under `mcp/tests/` (Python) or `tests/` (C++/ctest). Mock external
   backends (angr, IDA, Frida, the builder subprocess). Test
   fail-closed semantics explicitly. Bug fixes land as a regression
   test first, then the fix.
6. **Log at every meaningful boundary.** Python uses
   `logging.getLogger(__name__)`; C++ uses the project logger macros.
   INFO for one-line per-entry summaries, DEBUG for inner-loop
   detail, ERROR for fail-closed exits. Never `print` or
   `std::cout` in shipped code.
7. **No global mutable state.** Thread state through
   `ProtectionContext` (C++) or a `Session` plus constructor
   injection (Python). Test seams come from constructor arguments,
   never from module-level monkeypatching of production paths.
8. **Fail closed, never silent.** Backend crash, timeout, or missing
   tool must surface the error and report the worst-case metric. A
   `try/except: pass` anywhere is a review blocker.
9. **No dead or commented-out code.** No `// removed` blocks, no
   `_unused` shims, no backwards-compat leftovers. Delete it; git
   keeps the history.
10. **Match existing style exactly.** The pre-existing benchmarks
    and passes are the reference — register-decorator pattern, file
    headers, `_METRIC_DEFS` tables, helper sections. Do not invent
    parallel idioms.

Additional pipeline rules from the architecture:

- Every new pass gates via `ctx.target().is_...()` (e.g.
  `is_windows_pe_x64()`) and bails out cleanly on unsupported
  inputs — never crash on non-PE or non-x64 binaries.
- Architecture-specific code (encoders, emitters, rewriters, VM
  handlers) lives under an arch directory (`x64/`, future `arm64/`)
  behind an `arch::IXxxBackend` interface. Adding ARM64 is a new
  sibling, not edits to existing files. PE/ELF differences belong
  behind `pe::` / future `elf::` containers.
- Section names are never hard-coded; use `ctx.section_names()`
  (randomized per build).

## Pull requests

- Branch off `master`. Keep changes focused — one feature or fix
  per PR.
- Title format: `type(scope): summary`
  (e.g. `fix(vm): rax clobber in tail dispatch`), matching existing
  commit style.
- The full CI matrix (Windows + Linux) must be green before review.
- If your change adds a new pass, benchmark, or backend, ship its
  tests in the same PR.
- Update the relevant doc (`README.md`, `STABILITY.md`, `MCP.md`,
  `ROADMAP.md`) when your change alters user-visible behavior or
  the SDK contract.

## Reporting bugs

Open a GitHub issue with:

- affected commit SHA
- input PE (or a minimal reproducer)
- observed vs. expected behavior
- your environment (OS, compiler, CMake version)

## Security

Do not open public issues for vulnerabilities — see
[`SECURITY.md`](SECURITY.md) for the private reporting channel.

## License

By contributing you agree that your contribution is released under
the MIT license used by this project (see [`LICENSE`](LICENSE)).
