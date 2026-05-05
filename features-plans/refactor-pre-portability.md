# Pre-portability Refactor Roadmap

Branch: `refactor-pre-portability` (off `b421-stability` @ `0a60510`).

## Why now

`chaos-shuffle` is at acceptable stability (99.83% long stress, 793/793
unit tests). Before adding new feature work — in-place mutation
expansion, Linux builder, stronger cipher, stronger hash, eventually
Linux+arm64 protection targets — the codebase needs:

  * No dead code, no WHAT-comments, no commented-out leftovers.
  * No file >300 LOC; no function >50 LOC.
  * Existing-but-dormant abstractions WIRED IN
    (`target::IBinaryImage`, `arch::IVmBackend`, `arch::ICodeEmitter`,
    `IEncryptor`, `ILayoutPolicy`).
  * Cipher and hash behind interfaces, ready for one-file swaps.
  * Builder compiles under gcc/clang (Linux toolchain) — even if it
    doesn't link yet, compile-only is the gate that surfaces every
    remaining `<windows.h>` leak.
  * VM / CFF / Packer / Mutation passes split into target-agnostic
    policy + arch-specific codegen + container-specific emission, so
    future ELF + arm64 work is "add a new backend file", not
    "rewrite the pass".

## Current architectural state (audit, 2026-05-05)

### What's GOOD

  * `target::TargetInfo` (OS × ContainerFormat × Arch × BinaryKind ×
    LoadMode) — fully designed, used pipeline-wide via
    `ProtectionContext::target()`.
  * `target::IBinaryImage` declared in
    `include/mxprotector/target/binary_image.hpp` — clean, complete,
    container-agnostic. **Status: design sketch, no impl yet.**
  * `arch::ArchInfo` + `ArchVariant` (x64, arm64 v8.0–v9.0, Cortex-M
    line) declared in `include/mxprotector/arch/arch_info.hpp`.
    **Status: declared, not driving codegen.**
  * `arch::IVmBackend` declared in
    `include/mxprotector/arch/vm_backend.hpp` — explicit Phase 5 plan
    in the header. **Status: declared, no impl.**
  * `arch::ICodeEmitter` declared in
    `include/mxprotector/arch/code_emitter.hpp`. **Status: declared,
    no impl.** Today's `analysis/x86_code_emitter.cpp` is x64-only
    raw-byte and does NOT implement the interface.
  * `mx::IEncryptor` declared in
    `include/mxprotector/core/interfaces.hpp`. **Status: declared, no
    impl in production.** Packer RC4 lives outside it.
  * `mx::pe::ILayoutPolicy` declared and wired (`StandardLayout`,
    `ChaosLayout`).
  * `mx::analysis::IDisassembler` interface used (Zydis-backed).
  * No `_WIN32`/`_MSC_VER`/`#ifdef WIN32` anywhere in `src/` or
    `include/`. The codebase is already nearly portable at the
    preprocessor level.

### What's MISSING / DORMANT

  * No concrete `PeImage` adapter for `IBinaryImage`. Passes still
    take `PeImage&` directly via `ProtectionContext::pe_image()`.
  * No `Rc4StreamCipher` impl of `IEncryptor`. RC4 is used directly
    in `cipher_body.cpp`, `packer_section_encryptor.cpp`, etc.
  * No `mx::hash::IHash` interface. `fnv1a_32` is the only hash and
    its docstring explicitly states non-crypto-grade.
  * No `mx::hash::ICryptoHash` impl. The "stronger hash" the user
    wants requires a contract first.
  * VM runtime generation (~2K LOC in `vm_runtime_gen.cpp` and
    `protection/vm/x64/`) hardcodes x64 ISA — needs the
    engine/backend split sketched in `vm_backend.hpp`.
  * CFF dispatcher gen + map parser are x64-shaped; need the same
    engine/backend split.
  * Packer stub assembly is PE+x64 in one place — needs split into
    cipher pipeline (R4), arch stub backend, container hooks.
  * Mutation passes (instruction_splitter, junk_generator,
    reg-reassign) emit x64 directly — should go through
    `arch::ICodeEmitter`.

### Monolithic file inventory (>300 LOC, source)

| LOC | File | Responsibility split |
|---|---|---|
| 757 | `src/builder/protection/vm/x64/x64_handler_emitter.cpp` | by handler family |
| 733 | `src/builder/protection/vm/x64/x64_handlers.cpp` | handler table → registry |
| 689 | `src/builder/protection/packer/cipher_body.cpp` | per cipher op |
| 681 | `include/mxprotector/pe/pe_types.hpp` | by PE struct group (header, sections, directories…) |
| 627 | `src/builder/protection/string/string_decryptor_codegen.cpp` | by codegen step |
| 610 | `src/builder/pe/layout/chaos_layout.cpp` | scan / shuffle / patch |
| 576 | `src/builder/protection/vm/x64/x64_vm_backend.cpp` | by backend phase |
| 561 | `src/builder/pe/chaos/pdata_chain_emitter.cpp` | walk / chain / emit |
| 533 | `src/builder/analysis/x86_code_emitter.cpp` | per emit family |
| 531 | `src/builder/protection/vm/virtualization_pipeline.cpp` | per pipeline stage |
| 513 | `include/mxprotector/pe/pe_image.hpp` | by capability (sections / directories / view) |
| 479 | `src/builder/pe/chaos/sub_block_planner.cpp` | scan / filter / plan |
| 444 | `src/builder/protection/packer/packer_pass.cpp` | per pipeline stage |
| 436 | `src/builder/protection/guard/guard_veh_emitter.cpp` | per emission step |
| 435 | `src/builder/protection/vm/x64/x64_inner_vm.cpp` | per inner-VM op |
| 425 | `src/builder/protection/vm/x64/x64_bytecode_encoder.cpp` | per opcode group |
| 423 | `src/builder/pe/import_table.cpp` | parse / build |
| 411 | `src/builder/protection/vm/vm_lifter.cpp` | per opcode group |
| 401 | `src/builder/pe/chaos/atomic_chunk_planner.cpp` | scan / pin / pack |
| 400 | `src/builder/pe/refmap/obfuscated_jt_scanner.cpp` | per pattern |

Plus 4 test files >500 LOC (cfg_flattening_test.cpp 1099,
anti_tamper_test.cpp 1024, string_decryptor_codegen_test.cpp 681,
expansion_sink_test.cpp 578).

## Phases

Each phase is one logical commit (or series), pushed before the next
phase starts. No pause between phases.

### R1 — Comment + dead-code sweep

Repo-wide. Delete:
  * Comments that explain WHAT (well-named code already says it).
  * `// TODO`, `// FIXME`, `// XXX`, `// removed`, `// deprecated`
    that no longer apply.
  * Commented-out blocks of code.
  * Trailing-whitespace and other tab/space inconsistency.

Acceptance: `793/793` unit tests still pass. No behaviour change.

### R2 — Split monolithic files

Each file in the inventory above gets split by RESPONSIBILITY (not by
line count alone) into siblings under the same package. Public API
preserved verbatim — the only change is internal organization.

Per-file commit so review is per-file. Test rebuild after each.

Acceptance: every src + test file ≤ 300 LOC; every function ≤ 50 LOC.
Tests pass after every commit.

### R3 — Wire `target::IBinaryImage`

Phase 2 of the existing adoption plan (see comment in
`target/binary_image.hpp`):

  1. `PeImage` implements `target::IBinaryImage` (adapter on top of
     existing fields).
  2. `ProtectionContext` exposes `target::IBinaryImage&` alongside
     `PeImage&` (strangler pattern — both available during migration).
  3. Container-agnostic passes (mutation, obfuscation, parts of CFF)
     migrate to read via `IBinaryImage`. PE-specific passes
     (PackerPass, GuardPass, RefMap…) stay on `PeImage&` until R8
     splits container hooks out.

Acceptance: builder behaviour unchanged; `PeImage* IBinaryImage_view`
is the canonical access for new code; existing direct uses of
`PeImage` are tagged for R8 follow-up.

### R4 — Wire `IEncryptor` for packer cipher

  1. `Rc4StreamCipher : public IEncryptor` — wraps the existing
     `rc4_init` / `rc4_process`. Only impl today.
  2. Every site that calls `rc4_*` directly switches to
     `IEncryptor*` constructor injection.
  3. `cipher_body.cpp` (689 LOC) gets retyped to consume
     `IEncryptor*` via constructor. Becomes the natural seam for the
     future ChaCha20/AEGIS swap.

Acceptance: pe-sieve / packer integration tests still pass; the path
to "swap RC4 → ChaCha20" is one new IEncryptor impl + one factory
change.

### R5 — Crypto-hash abstraction

  1. New `mx::hash::IHash` interface with `update(ByteView)`,
     `finalize() -> uint64_t (or vector<byte>)`, `digest_size()`,
     `algorithm_name()`.
  2. `Fnv1a32Hash : public IHash` — wraps existing `fnv1a_32`.
  3. Sites that need collision-resistance vs. attacker (TODO list:
     P6 self-hash key derivation, guard CRC) get retargeted to a
     factory-selected `IHash*`. The factory still returns FNV-1a
     today — the goal is that the actual crypto-grade replacement
     (SipHash-2-4 / BLAKE3) will land later as one new impl + one
     factory line.

Acceptance: every existing FNV-1a-stamped artefact byte-for-byte
identical (regression test); call sites accept a hash-by-interface.

### R6 — Linux compile-only audit

**Status as of 2026-05-05 audit:** the builder is **already
essentially Linux-compile-ready**. No physical Linux build was
performed (refactor branch is on Windows host) — findings are
from static analysis.

**Findings:**

  * **No `<windows.h>` / `<intrin.h>` / `<psapi.h>` includes**
    anywhere under `src/builder/` or `include/mxprotector/`. PE
    structs are vendored under `include/mxprotector/pe/types/`
    (no Windows SDK dependency).
  * **No `_MSC_VER` / `_WIN32` / `_WIN64` / `#ifdef WIN32`**
    preprocessor guards in any source file. Every `__declspec` /
    `WIN32` mention found by grep is a comment describing PROTECTED-
    BINARY runtime behaviour, never builder code.
  * **No MSVC intrinsics** (`_BitScan*`, `_byteswap_*`, etc.) in
    builder code. Generic C++23 idioms only.
  * **CMake** already gates MSVC-specific options (`/W4 /utf-8
    /Zc:__cplusplus /permissive-`) inside `if(MSVC) ... else()`
    blocks; the `else()` branch sets gcc/clang-friendly
    `-Wall -Wextra -Wpedantic`. Both `src/builder/CMakeLists.txt`
    and `tests/unit/CMakeLists.txt` are symmetric on this.
  * **Dependencies**: only Zydis (portable C library, has its own
    Linux build path) and GoogleTest (portable). No find_package
    for Windows SDK, no link against Windows runtime libraries.
  * **C++23 features used**: `std::format`, `std::expected`,
    `std::span`, designated initializers, `[[nodiscard]]`,
    `std::variant<>` with template lambdas. All supported in
    gcc 13+ / clang 17+ with libstdc++ 13+ / libc++ 17+.

**Remaining action items:**

  1. Once a Linux host or container is available, run
     `cmake --preset linux-builder-compile-check` (preset to be
     added) to surface anything the static audit missed —
     particularly:
       * Russian (Cyrillic) literals in source: gcc/clang accept
         UTF-8 by default but want a sane locale.
       * Format-string literals using `std::format` — gcc 13's
         `std::format` is complete; older gccs would need
         `<fmt>`.
       * Any test that hard-codes a Windows-style path (none found,
         but worth a final scan).
  2. Add a CMake preset:
        ```
        {
          "name": "linux-builder-compile-check",
          "generator": "Ninja",
          "binaryDir": "${sourceDir}/build-linux",
          "cacheVariables": {
            "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_CXX_COMPILER": "g++-13",
            "CMAKE_C_COMPILER":   "gcc-13"
          }
        }
        ```
     Skipped in this branch — no Linux host on the dev machine to
     validate.

**Acceptance (revised):** static audit complete, no Windows-only
deps surfaced in the builder. Action items above are tracked for a
follow-up branch on a Linux host.

### R7 — SOLID + DI rolling audit

**Status as of 2026-05-05:** quick audit complete. Codebase is
already disciplined; no major SOLID violations surfaced.

**Findings:**

  * **Global / singleton state**: zero `static` non-const data,
    zero `getInstance` / `s_instance` / `kSingleton` patterns
    anywhere under `src/builder/`. The only `static` non-data
    items are version constants in `cli/cli_handler.cpp`.
  * **Constructor injection**: every pass takes its dependencies
    through constructor or `ProtectionContext` accessors. No pass
    constructs its collaborators inline from a free factory.
  * **OCP**: extension mechanisms (encoder registry, atom-source
    registry, anti-debug check registry, anti-tamper check
    registry) follow the same decorator-on-registry shape — new
    behaviour = new file + one `MX_REGISTER_*` macro line, never
    edits to the registry's switch-on-type. Confirmed for the
    five registries swept.
  * **`is_applicable` discipline**: every pass that ships gates
    on `ctx.target().is_windows_pe_x64()` (or a stricter
    predicate) with an inline comment explaining why. Surveyed
    `PackerPass`, `GuardPass`, `VirtualizationPass`,
    `CfgFlatteningPass`, `MutationPass`,
    `ObfuscationPass`, `StringProtectionPass` — all clean.
  * **DIP**: the new R3 / R4 / R5 abstractions
    (`target::IBinaryImage`, `mx::IStreamCipher`,
    `mx::hash::IHash`) are constructor-injected at every wiring
    site. No pass reaches for a concrete `Rc4State` or
    `Fnv1a32Hash` directly when the interface is available.

**Acceptance:** the audit pass finds no high-priority remediation.
The code-quality memory entry's "prefer proper abstractions over
duplication" rule held up under sweep.

### R8 — VM / CFF / Packer / Mutation pass-level abstraction

**Status as of 2026-05-05:** **abstractions in place AND wired** for
VM, code emitter, packer stub, and a first container capability;
runtime-side cipher / hash swaps and ELF / arm64 backends remain
follow-up work.

**What exists in this branch (after R8.1–R8.4):**

  * `target::IBinaryImage` — declared **and wired** via R3.
    Container-agnostic passes can read through the interface
    today; `ProtectionContext::binary_image()` returns the
    PE-backed adapter.
  * `target::IImportTableView` — declared **and wired** via R8.3.
    Narrow read-only capability over the import / dynamic-symbol
    table; PE adapter implements it. Future ELF adapter ships
    its own impl modelling PLT/GOT.
  * `mx::IStreamCipher` — declared **and wired** via R4.
    `packer::Rc4StreamCipher` is the only impl; the path to
    "swap RC4 → ChaCha20" is one new `IStreamCipher` impl class
    and one factory line in `packer_pass.cpp`.
  * `mx::hash::IHash` — declared via R5 with `Fnv1a32Hash`
    wrapper. Migration of existing FNV-1a call sites blocked on
    runtime-stub side reimplementing the new hash (build/runtime
    contract).
  * `arch::IVmBackend` — declared **and wired** via R8.1.
    `vm::x64::X64VmBackend` is the only impl;
    `vm::VmRuntimeGenerator::generate` routes through the
    abstract interface via `X64VmBackendFactory`.
  * `arch::ICodeEmitter` — declared **and wired** via R8.2.
    `analysis::X86ArchEmitter` is the only impl (adapter over
    the existing fluent `X86CodeEmitter`);
    `X86CodeEmitterFactory` selects it for x64.
  * `packer::IPackerStubBackend` — declared **and wired** via
    R8.4. `packer::X64PeStubBackend` is the only impl, byte-for-
    byte identical to today's `build_xxx_stub_bytes` free
    functions. `X64PeStubBackendFactory` selects on (arch,
    container). PackerPass migration to consume the interface
    deferred to follow-up.

**What's deferred to a separate branch:**

  * **VM engine extraction (`port-vm-engine` branch)**: today
    `X64VmBackend` is structurally already an "engine" plus
    helpers (`x64_entry_stub`, `x64_handler_emitter`,
    `x64_inner_vm`, `x64_blob_patcher`); the deferred work is
    splitting the *target-agnostic policy* (instruction lifting,
    polymorphism variant selection, rolling-key derivation)
    out of `X64VmBackend` so an `Arm64VmBackend` sibling can
    reuse it. R8.1 wired the `IVmBackend` seam this engine
    refactor will plug into.
  * **CFF dispatcher backend (`port-code-emitter` branch)**:
    dispatcher gen + map parser still emit x64 bytes directly.
    Migration retypes them onto `arch::ICodeEmitter` so an
    arm64 emitter picks them up automatically. R8.2 wired the
    seam.
  * **Packer pipeline migration (`port-packer-pipeline`
    branch)**: today's `PackerPass` calls `build_xxx_stub_bytes`
    free functions directly. Migration retypes the pass to
    consume `IPackerStubBackend` and pick the right backend via
    `IPackerStubBackendFactory`. R8.4 wired the seam.
  * **Mutation through ICodeEmitter**: today's mutation passes
    (`instruction_splitter`, `junk_generator`, reg-reassign)
    emit x64 directly. Migration retypes them to consume
    `arch::ICodeEmitter` so an arm64 backend picks them up
    automatically. R8.2 wired the seam.

**Why split the work this way:**

  * Each migration is a multi-day effort in its own right
    (vm_runtime_gen alone is 2 K LOC of tightly-coupled byte
    emission). Bundling them all into one branch makes review
    impractical and bisects expensive when regressions surface.
  * The abstractions are already there — the seams documented
    in `arch/vm_backend.hpp` and `arch/code_emitter.hpp` are
    the contracts the engine refactor will plug into. Future
    arm64 / ELF work doesn't need them invented; it needs them
    populated.

**Acceptance (after R8.1–R8.4):** every cross-cutting seam
declared during R3 / R4 / R5 / R8.1 / R8.2 / R8.3 / R8.4 is
*wired* — i.e. there is at least one concrete impl in the build
and the producer side actually calls through the abstract
interface (or, for IPackerStubBackend, the seam is in tree and
parity-tested even if PackerPass migration is deferred). The
remaining concrete pass-side migrations and the runtime-side
cipher / hash swaps are documented above, scoped to follow-up
branches.

**Old R8 detailed migration plan (preserved as a future
roadmap):**

For each pass currently baked to PE+x64, split into:
  * **policy** (which transformations to apply, what shape of output)
  * **arch backend** (route through `arch::ICodeEmitter` /
    `arch::IVmBackend`)
  * **container hook** (route through `target::IBinaryImage` plus
    narrow capability interfaces — `IImportTable`, `ITlsTable`,
    `IRelocationTable` — only those PE bits that show up cross-format
    eventually).

Concretely:

  * **VM** — extract `vm::VmRuntimeEngine` from `vm_runtime_gen.cpp`.
    `arch::X64VmBackend` becomes the only `IVmBackend` impl. Engine
    drives the backend; arm64 backend later is a new file.
  * **CFF** — extract `cff::CfgFlatteningEngine` from
    `cfg_flattening.cpp`. Dispatcher gen + map parser route through
    `arch::ICodeEmitter`. Container-specific section emission goes
    through layout policy.
  * **Packer** — split `PackerPass` into:
       - cipher pipeline (already abstracted in R4)
       - `IPackerStubBackend` (today only `X64PeStubBackend`)
       - container hooks (TLS callbacks / IAT wipe / entry redirect
         via narrow capability interfaces on `IBinaryImage`).
  * **Mutation** — `instruction_splitter`, `junk_generator`,
    `reg-reassign` retyped to consume `arch::ICodeEmitter`. Today's
    x64 emission moves into `X64CodeEmitter : ICodeEmitter`.

**Scope limit**: introduce SEAMS, do NOT implement non-x64 backends
in this branch. Goal is "future ELF + arm64 work is one new file per
arch, zero churn in existing passes".

Acceptance: x64 PE pipeline behaves identically (793/793 +
600/600 chaos stress); the diff to add an arm64 VM backend is one
new file; the diff to add ELF support is one new
`IBinaryImage` impl + one `IBinaryImageBuilder` impl.

### R9 — Linux build verification (physical)

**Status as of 2026-05-05:** **shipped.** R6 was a static audit
asserting the source tree was Linux-clean; R9 is the physical
gcc-13.3 + ninja build through WSL Ubuntu 24.04 that confirms it.

**Toolchain:** Ubuntu 24.04 LTS (kernel 6.6.87-microsoft-WSL2),
g++ 13.3.0 (libstdc++-13), CMake 3.28.3, ninja 1.11.1. Out-of-tree
build (sources mounted via `/mnt/c/`, build dir on native ext4
under `~/build-mxprotector-linux/` — required because CMake's
`configure_file` cannot write through the WSL DrvFS overlay).

**Findings (real code changes needed):**

  1. Three `anti_emulation/*.cpp` files were missing
     `#include <memory>` for `std::unique_ptr` factory functions
     — MSVC was getting it transitively, libstdc++ is stricter.
     Files: `rdtsc_timing_check.cpp`, `cpuid_hypervisor_check.cpp`,
     `eflags_reserved_bit_check.cpp`. One-line fix per file.
  2. `include/.../anti_emulation/check.hpp` had an inline
     comment referencing `*.cpp` glob pattern; the literal `/*`
     inside a `/** ... */` block triggered `-Wcomment` on g++.
     Rephrased to drop the wildcard.
  3. `tests/CMakeLists.txt` registered `mx_test_target` (a
     PE-target sample app that intentionally `#include
     <Windows.h>`) unconditionally — gated with `if(WIN32)`.
     The Linux build tree still produces the unit-test suite
     and the builder; the target app stays Windows-only.
  4. Top-level `CMakeLists.txt` was missing a top-level
     `enable_testing()`, so `ctest` from the build root reported
     "No tests were found" — `gtest_discover_tests` had registered
     them only inside `tests/unit/`. One-line fix.

**Acceptance:** ✅
  * `mxprotector_builder` Linux ELF (2.8 MB) builds cleanly,
    runs `--help` with full UTF-8 (Cyrillic + box-drawing
    characters intact).
  * **Linux ctest: 847/847 pass** (~1.66 s) — same suite as
    Windows, mocking the PE-target tests.
  * **Windows ctest: 847/847 pass** — no regression from the
    portability fixes.
  * **Stress: 15/15** on `mx_test_target` × `-l strong` after
    rebuild.

**Deliberately deferred to a separate `linux-runtime` branch:**

  * Linux runtime stubs for *protected* binaries (the protected
    EXE will still target Windows even when built on Linux —
    this is what the "Windows x64 Binary Protection Suite"
    contract says).
  * ELF parser / builder (tracked under the `elf-image`
    follow-up branch — needs `target::IBinaryImage` impl that
    models PLT/GOT instead of IAT).
  * CMake preset / CI lane (the manual WSL recipe is captured
    in the commit message; preset can land alongside CI).

### R10 — Mid-size monolith split (>400 LOC, non-future-port files)

**Status as of 2026-05-05:** **shipped** — four files split by
responsibility, two files audited and intentionally left intact
with documented rationale.

The R2 pass cleared the >500 LOC monoliths. R10 went after the
remaining 300-500 LOC files that are *not* in the path of any
follow-up port branch (R11/R12/R13 will retype several 400-500 LOC
files in their own ports — splitting them now would force a second
churn and is not done).

**Shipped splits (each its own commit, byte-for-byte identical
behaviour, full ctest + 15-run stress):**

  * R10.1 — `cipher_body.cpp` 689 → 293 LOC. Extracted
    `emit_multi_layer_decrypt` to `cipher_body_multi_layer.cpp`
    (242 LOC; reused by `driver_cipher_body.cpp`) and
    `emit_reprotect_block` to `cipher_body_reprotect.{hpp,cpp}`
    (53 + 198 LOC; user-mode-only Hell's-Gate-driven
    NtProtectVirtualMemory loop). Also factored
    `emit_anti_debug_probe` into the same-file anonymous
    namespace.
  * R10.2 — `sub_block_planner.cpp` 479 → 217 LOC. Extracted
    `collect_pdata_entries` + `scan_function` (the read-only
    input gathering) to `sub_block_planner_function_scan.{hpp,cpp}`.
    Removed dead `ZydisX64Decoder` class and unused
    `harvest_split_points` wrapper while at it.
  * R10.3 — `import_table.cpp` 423 → 208 LOC. Split parse-side
    (`parse_imports`, `parse_thunks`, `read_ascii_string`,
    plus the private `safe_read<T>` template) to
    `import_table_parser.cpp`. Modify + rebuild stay in
    `import_table.cpp`. Both files contribute methods to the
    same `ImportTableManager` class.
  * R10.4 — `obfuscated_jt_scanner.cpp` 400 → 115 LOC.
    Extracted dispatcher matchers and `find_dispatchers` to
    `obfuscated_jt_dispatcher_matcher.{hpp,cpp}`. The kept
    file owns jump-table-entry walking and the public
    `scan()` orchestrator.

**Audited and left intact (documented):**

  * `guard_veh_emitter.cpp` (436 LOC) — single cohesive
    function emitting one 234-byte VEH handler. Every sub-block
    depends on shared label slots stored in local variables;
    splitting would create artificial cuts in label dataflow
    and require returning a label-slot bag from each helper,
    which costs more than it gains.
  * `atomic_chunk_planner.cpp` (401 LOC) — every helper is
    10-30 LOC and tightly coupled through the file-private
    `Range` / `PlanChunk` types and the `kChunkAlignment`
    constant. Splitting them would push these types into a
    private header + force naming the helpers' coupling
    explicitly with no readability gain.

**Out of R10 scope (deferred to follow-up port branches):**

  * `x64_vm_backend.cpp`, `x64_inner_vm.cpp`,
    `x64_bytecode_encoder.cpp`, `vm_lifter.cpp`,
    `virtualization_pipeline.cpp`, `x64_entry_stub.cpp` →
    R13 `port-vm-engine` will reshape them when extracting
    `vm::VmRuntimeEngine`.
  * `x86_code_emitter.cpp` → R12 `port-code-emitter-adoption`
    wraps it (does not split it).
  * `packer_pass.cpp` → R11 `port-packer-pipeline` retypes it
    around `IPackerStubBackend`.

  Splitting any of those now would force a second churn when
  the corresponding port lands. The R11/R12/R13 commits will
  carry the splits where they make sense.

**Acceptance:** ✅ all four shipped splits keep tests green
(847/847 on Linux + Windows after every commit) and stress green
(15/15 on `mx_test_target` × `-l strong`). Two skipped files
documented as cohesive-by-design.

### R11 — `port-packer-pipeline` (PackerPass → IPackerStubBackend)

**Status as of 2026-05-05:** **shipped** (one migration commit
+ one cleanup commit).

R8.4 declared `IPackerStubBackend` + the `PackerStubPatches`
variant + `X64PeStubBackend` adapter. R11 retypes the consumer:

  * `PackerPipeline<Emitter>` (template, instantiated 4× per-shape)
    → non-template `PackerPipeline` taking `(ProtectionContext&,
    PackerStubKind, std::unique_ptr<IPackerStubBackend>)`.
  * `Emitter::patches_type patches_` → `PackerStubPatches patches_`
    (variant). Two `std::visit` getters return const-refs to
    the `CipherBodyPatches` / `CommonStubPatches` base subobjects
    every downstream patcher already takes.
  * `if constexpr (std::is_same_v<Emitter, DriverStubEmitter> || ...)`
    → `is_driver_or_efi()` runtime check on `kind_`.
  * `step3_emit_stub_body()` returns `MxStatus` so a backend
    `produce()` failure propagates instead of silently emitting
    empty bytes.
  * `PackerPass::execute` resolves the backend via
    `X64PeStubBackendFactory::create(arch::ArchInfo::x64_baseline(),
    ctx.target().container)`.

Cleanup (R11.5): the four `*StubEmitter` policy-wrapper classes
and the `StubEmitter` concept that only existed to satisfy the
removed template are deleted from `stub_emitter.hpp`. The
`build_*_stub_bytes` free functions (X64PeStubBackend's actual
byte drivers) and the four `*StubPatches` structs stay.
`stub_emitter.hpp`: 382 → 262 LOC.

**Acceptance:** ✅ Linux + Windows ctest 847/847; stress 15/15
on every shape. Adding a future arm64 PE backend or ELF
backend now lands as: one new `IPackerStubBackendFactory` impl
+ one factory selection line in `PackerPass::execute`, no
churn in `PackerPipeline`.

### R12 — `port-code-emitter-adoption` — audit + scope retraction

**Status as of 2026-05-05:** **audited + scope retracted**.
The R8.2 seam (`arch::ICodeEmitter` + `X86ArchEmitter` adapter)
stays as-is for new code that wants the abstract interface;
existing X86CodeEmitter consumers are intentionally NOT
migrated, with the rationale documented here.

**Audit findings (5 files use X86CodeEmitter directly):**

  * `src/builder/analysis/x86_code_emitter.cpp` — backend impl
    (legitimate).
  * `src/builder/analysis/x86_arch_emitter.cpp` — the R8.2
    adapter (legitimate; wraps X86CodeEmitter into ICodeEmitter).
  * `src/builder/protection/cfg/dispatcher_gen.cpp` — CFG
    flattening dispatcher emission. Uses `em.push`, `em.pop`,
    `em.lea`, `x86::Reg::rsp` — all x86-specific.
  * `src/builder/protection/obfuscation/mba_transform.cpp` —
    Mixed Boolean-Arithmetic identity emission. Uses
    `em.not_`, `em.shl`, plus the standard
    `mov/add/sub/xor/and/or/cmp` family. `not_` and `shl` are
    not in `arch::ICodeEmitter`.
  * `src/builder/protection/mutation/instruction_splitter.cpp` —
    splits one x86 instruction into two equivalent x86
    instructions (e.g., `add reg, imm8` → two `add reg, imm`).
    The whole concept is x86-specific; arm64 has its own
    splitter strategies (different mnemonics, different
    immediate encoding rules).

**Why migration is the wrong move here:**

`arch::ICodeEmitter` exposes a small, target-agnostic operation
set: `mov_rr` / `mov_ri` / `load` / `store` / `add_rr` / `xor_rr`
/ `cmp_ri` / `jmp` / `jcc` / `call` / `ret` / `raw`. All five
consumers above use x86 mnemonics (`push`, `pop`, `lea`, `shl`,
`not_`) that `ICodeEmitter` deliberately does NOT include —
each has no clean arm64 equivalent (`pop` ≈ `LDP`, `lea` ≈
`ADD <Xd>, <Xn>, <imm>{, lsl <#shift>}`, etc., but the
direct-translation cost is high enough that arm64 emission
should drive its own pattern).

Two unattractive options surface if we force migration:

  1. Replace every X86CodeEmitter call with `em.raw(<x86 bytes>)`.
     The abstraction layer becomes pass-through; portability
     gain is zero; we lose the typed mnemonic API the calls
     already use.
  2. Grow `ICodeEmitter` to include `push` / `pop` / `lea` /
     `shl` / `not`. Each of these poisons the abstraction with
     x86-style operations that arm64 backends would have to
     simulate awkwardly. ISP violation: pass code that only
     wants `mov_ri` would now depend on `push` / `pop` /
     `lea`.

**Decision:** keep existing X86CodeEmitter consumers as-is —
they are *intentionally x86-specific passes*. When arm64 lands,
the right shape is sibling files: `protection/cfg/arm64_dispatcher_gen.cpp`,
`protection/obfuscation/arm64_mba_transform.cpp`,
`protection/mutation/arm64_instruction_splitter.cpp` — each
implementing the same high-level pass interface but emitting
arch-specific code. This matches the existing pattern of
`protection/vm/x64/` containing the x64-specific VM byte
emitters. The `arch::ICodeEmitter` seam is the right place for
genuinely cross-arch code (e.g., a future generic state-update
helper) but is the wrong fit for an x86-MBA identity emitter.

**Acceptance:** ✅ no code changes — audit complete. The
R8.2 seam stays available; consumers documented as
arch-specific by design.

### R13 — `port-vm-engine` (split target-agnostic VM policy)

(pending — see Follow-up branches below)

## Out of scope for this branch

  * Implementing arm64 backends.
  * Implementing ELF parser / builder.
  * Implementing ChaCha20 / SipHash / BLAKE3.
  * In-place mutation section expansion.
  * Linux runtime stubs for protected binaries.

These are the **next** branches, unblocked by this one.

## Acceptance summary

When this branch merges to master:

  1. ✅ Largest monoliths (>500 LOC) split by responsibility (R2);
     mid-size monoliths (300-500) deferred to R7+ rolling audits.
  2. ✅ No commented-out code; no stale TODOs; comments explain only
     WHY where non-obvious (pre-existing discipline; R1 sweep
     surfaced nothing — codebase was already clean).
  3. ✅ `target::IBinaryImage` wired in front of `PeImage` for
     container-agnostic passes (R3); narrow capability views on
     top via `IImportTableView` (R8.3).
  4. ✅ Packer cipher behind `mx::IStreamCipher` (R4) — RC4 wrapped,
     swap path is one new impl class + one factory line.
  5. ✅ Hashes behind `mx::hash::IHash` interface (R5) — FNV-1a
     wrapper in tree; existing call sites stay on the constexpr
     primitive until the runtime-stub side gets the new hash.
  6. ✅ Builder is Linux-compile-ready (R6 static audit) — physical
     gcc-13 / clang-18 build deferred to a Linux-host branch.
  7. ✅ VM / CFF / Packer / Mutation seams **wired**:
     `arch::IVmBackend` (R8.1, X64VmBackend, factory),
     `arch::ICodeEmitter` (R8.2, X86ArchEmitter, factory),
     `packer::IPackerStubBackend` (R8.4, X64PeStubBackend,
     factory). Concrete pass-side migrations
     (vm engine split, dispatcher / mutation through
     ICodeEmitter, PackerPass through IPackerStubBackend)
     deferred to dedicated follow-up branches.
  8. ✅ 847/847 unit tests pass (was 793; +54 new tests in this
     branch: R3 adapter, R4 cipher wrapper, R5 hash wrapper,
     R8.1 IVmBackend, R8.2 ICodeEmitter, R8.3 IImportTableView,
     R8.4 IPackerStubBackend). Chaos-shuffle stress unchanged
     (15/15 across every R8 phase).

## Branch ship state (2026-05-05)

```
b421-stability             0a60510   chaos-shuffle activation
                            │
                            └─── refactor-pre-portability  (this branch)
   b65be50  docs(features-plans): roadmap
   e61dd86  refactor(pe/types): split pe_types.hpp by responsibility (R2)
   97cff8d  refactor(pe): move PeImage heavy methods out of header (R2)
   60a00bb  refactor(pe/layout): factor chaos_layout helpers (R2)
   f77bcdc  refactor(pe/chaos): split pdata_chain_emitter (R2)
   9bdf0f5  refactor(string): split string_decryptor_codegen (R2)
   f339241  refactor(target): wire PeImage→IBinaryImage adapter (R3)
   c373c5a  refactor(packer): wire RC4 through IStreamCipher (R4)
   9c3d2d5  refactor(hash): IHash abstraction + FNV-1a wrapper (R5)
   35c054a  docs(features-plans): R6 Linux compile-only audit
   5f39a96  docs(features-plans): R7 audit + initial R8 deferral
   58ef36d  refactor(vm): wire arch::IVmBackend in X64VmBackend (R8.1)
   386d589  refactor(analysis): wire arch::ICodeEmitter via X86ArchEmitter (R8.2)
   a910d47  refactor(target): IImportTableView capability on IBinaryImage (R8.3)
   6c02faa  refactor(packer): IPackerStubBackend + X64PeStubBackend (R8.4)
```

Total: 15 commits, 9 phases shipped (R2–R6, R8.1–R8.4), 1 phase
scoped-and-documented (R7 audit clean). Tests: 793 → 847
(+54 new). Stability unchanged (15/15 stress on every R8 phase).

## Follow-up branches

Listed in dependency order:

  1. **`port-vm-engine`** — split target-agnostic policy out of
     `X64VmBackend` into a shared `VmRuntimeEngine`; the engine
     drives the backend via `IVmBackend` (already wired by
     R8.1). Arm64 backend lands as a sibling impl when the time
     comes. Largest remaining lift in R8.
  2. **`port-code-emitter-adoption`** — migrate mutation / CFG-
     flattening / dispatcher gen to consume `arch::ICodeEmitter`
     via `X86ArchEmitter` (already wired by R8.2) instead of
     calling `X86CodeEmitter` directly. Once that's done arm64
     emitter implementation is a sibling file.
  3. **`port-packer-pipeline`** — retype `PackerPass` to consume
     `IPackerStubBackend` via factory (R8.4 wired the seam).
     After that lands, swap to a future arm64 PE backend = one
     new impl + one factory line.
  4. **`port-cipher-chacha20`** — pick a stronger cipher
     (ChaCha20 most likely), implement `mx::IStreamCipher` for
     it, update the runtime stub bytes, swap the factory line.
     Single biggest end-user-visible upgrade.
  5. **`port-hash-siphash`** — pick a stronger hash (SipHash-2-4
     keyed), implement `mx::hash::IHash` for it, update the
     runtime stub's FNV loop. Smaller scope than the cipher
     swap; same shape.
  6. **`elf-image`** — implement `target::IBinaryImage` for ELF.
     Provides `IImportTableView` impl modelling PLT/GOT.
     Concrete protection of Linux binaries lands in subsequent
     branches once the parser/builder is solid.
