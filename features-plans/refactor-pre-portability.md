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

  1. CMake adds a Linux preset (gcc-13 + clang-18 + libstdc++ /
     libc++).
  2. Compile-only smoke target — no link, no artefacts. Goal is to
     *surface* every remaining `<windows.h>` / `HANDLE` /
     `GetProcAddress` etc. usage in the BUILDER (NOT the protected
     runtime stubs; those stay PE+x64).
  3. Every surfaced gap gets either:
       * a small `mx::platform::*` shim with Windows + POSIX impls,
         OR
       * a documented "leave for later" item in this file.

Acceptance: `cmake --preset linux-builder-compile-check` green.

### R7 — SOLID + DI rolling audit

Walk every pass / manager class and the largest classes in the
monoliths split during R2. Catch:
  * Single-Responsibility violations (split off helpers).
  * Open-Closed violations (extend via registry decorator, not by
    `if/else` chains in core).
  * Dependency Inversion violations (constructor inject the
    abstraction, never the concrete class).
  * Remaining global / singleton state (move into context or
    constructor-injected).

Fix as found. Per-finding commit.

Acceptance: code-quality memory entry no longer triggers on the
files audited.

### R8 — VM / CFF / Packer / Mutation pass-level abstraction

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

  1. Every src + test file ≤ 300 LOC; every function ≤ 50 LOC.
  2. No commented-out code; no stale TODOs; comments explain only
     WHY where non-obvious.
  3. `target::IBinaryImage` wired in front of `PeImage` for
     container-agnostic passes.
  4. Packer cipher behind `IEncryptor`.
  5. Hashes behind `mx::hash::IHash` interface.
  6. Builder compiles cleanly under gcc-13 / clang-18 (compile-only).
  7. VM / CFF / Packer / Mutation each have a single `arch backend`
     seam, ready for arm64 to drop in as a new file.
  8. 793/793 unit tests pass; chaos-shuffle stress unchanged
     (≥ 99.5%).
