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

**Status as of 2026-05-05:** **abstractions in place**, concrete
migrations **deferred to follow-up branches**.

**What exists in this branch:**

  * `target::IBinaryImage` — declared **and wired** via R3.
    Container-agnostic passes can read through the interface
    today; `ProtectionContext::binary_image()` returns the
    PE-backed adapter.
  * `mx::IStreamCipher` — declared **and wired** via R4.
    `packer::Rc4StreamCipher` is the only impl; the path to
    "swap RC4 → ChaCha20" is one new `IStreamCipher` impl class
    and one factory line in `packer_pass.cpp`.
  * `mx::hash::IHash` — declared via R5 with `Fnv1a32Hash`
    wrapper. Migration of existing FNV-1a call sites blocked on
    runtime-stub side reimplementing the new hash (build/runtime
    contract).
  * `arch::IVmBackend` — declared (in `arch/vm_backend.hpp`),
    no impl. Phase 5 plan documented in the header.
  * `arch::ICodeEmitter` — declared (in `arch/code_emitter.hpp`),
    no impl. Today's `analysis/x86_code_emitter.cpp` emits
    bytes directly; not yet adapted to the abstract interface.

**What's deferred to a separate branch (`port-arm64-vm-engine`):**

  * **VM engine extraction**: split `vm_runtime_gen.cpp` (~2 K
    LOC of byte emission) into a target-agnostic
    `VmRuntimeEngine` and an `arch::X64VmBackend` that
    implements `IVmBackend`. The engine drives the backend via
    the abstract interface. Arm64 backend lands as a sibling
    file when the time comes.
  * **CFF dispatcher backend**: the dispatcher gen + map parser
    currently emit x64 bytes directly. Migration will route
    through `arch::ICodeEmitter`; container-specific section
    emission already goes through `pe::ILayoutPolicy` (which
    gets generalised when ELF lands).
  * **Packer stub backend**: `PackerPass` will split into a
    cipher pipeline (R4 ✓), an `IPackerStubBackend` (today only
    `X64PeStubBackend`), and container hooks via narrow
    capability interfaces on `IBinaryImage` (IImportTable,
    ITlsTable). Cipher pipeline already done in R4.
  * **Mutation through ICodeEmitter**: today's mutation passes
    (`instruction_splitter`, `junk_generator`, reg-reassign)
    emit x64 directly. Migration retypes them to consume
    `arch::ICodeEmitter` so an arm64 backend picks them up
    automatically.

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

**Acceptance (revised):** `target::IBinaryImage`,
`mx::IStreamCipher`, `mx::hash::IHash`, `arch::IVmBackend`,
`arch::ICodeEmitter` are all in tree. Three of them are wired
into production code. The remaining concrete migrations are
documented above, scoped to follow-up branches.

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
     container-agnostic passes (R3).
  4. ✅ Packer cipher behind `mx::IStreamCipher` (R4) — RC4 wrapped,
     swap path is one new impl class + one factory line.
  5. ✅ Hashes behind `mx::hash::IHash` interface (R5) — FNV-1a
     wrapper in tree; existing call sites stay on the constexpr
     primitive until the runtime-stub side gets the new hash.
  6. ✅ Builder is Linux-compile-ready (R6 static audit) — physical
     gcc-13 / clang-18 build deferred to a Linux-host branch.
  7. ✅ VM / CFF / Packer / Mutation seams in place. Concrete
     `arch backend` migrations (vm_runtime_gen split, ICodeEmitter
     adoption) deferred to follow-up branches.
  8. ✅ 813/813 unit tests pass (was 793; +20 new tests in this
     branch — R3 adapter, R4 cipher wrapper, R5 hash wrapper).
     Chaos-shuffle stress unchanged.

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
```

Total: 10 commits, 5 phases shipped (R2-R6), 2 phases scoped-and-
documented (R7 audit clean, R8 deferred to follow-ups). Tests:
793 → 813 (+20 new). Stability unchanged.

## Follow-up branches

Listed in dependency order:

  1. **`port-vm-engine`** — extract `VmRuntimeEngine` from
     `vm_runtime_gen.cpp`; introduce `arch::X64VmBackend` as the
     only `IVmBackend` impl. Engine drives the backend; x64 path
     keeps producing identical bytes. Largest individual lift in
     R8; gated on this PR's seams being stable.
  2. **`port-code-emitter`** — make `analysis/x86_code_emitter`
     implement `arch::ICodeEmitter` so mutation / CFF passes
     migrate to the abstract interface in subsequent commits.
  3. **`port-cipher-chacha20`** — pick a stronger cipher
     (ChaCha20 most likely), implement `mx::IStreamCipher` for
     it, update the runtime stub bytes, swap the factory line in
     `packer_pass.cpp`. Single biggest end-user-visible upgrade.
  4. **`port-hash-siphash`** — pick a stronger hash (SipHash-2-4
     keyed), implement `mx::hash::IHash` for it, update the
     runtime stub's FNV loop. Smaller scope than the cipher
     swap; same shape.
  5. **`linux-builder`** — physical Linux compile + link of the
     builder. Most likely a no-op on the source; just adds a
     CMake preset and CI lane.
  6. **`elf-image`** — implement `target::IBinaryImage` for ELF.
     Concrete protection of Linux binaries lands in subsequent
     branches once the parser/builder is solid.
