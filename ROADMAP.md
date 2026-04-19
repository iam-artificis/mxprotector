# MxProtector Roadmap

**Rule:** Stress test (15/15 strong, EXE + DLL + unit tests) before every push.

## In Progress — Driver / manual-map support
Priority order: **manually-mapped .sys → manually-mapped DLL → OS-loaded .sys → OS-loaded DLL**.
Exceptions / `MX_GUARD` have no ring0 analogue, so guarded regions in drivers are explicitly unsupported.
- **Stage 1 — Foundation (done):** `TargetInfo` extended with `BinaryKind` (executable / dynamic_library / kernel_driver) and `LoadMode` (os_loaded / manual_mapped). CLI flag `--load-mode=os|manual`. `GuardPass`, `StringProtectionPass`, `PackerPass` skip kernel drivers. Unit tests pin the predicates + gates.
- **Stage 2 — Kernel-safety audit (done):** Audited VM / Mutation / Obfuscation / CFG / StringProtection runtime output against ring0 constraints. Findings:
  - Mutation / Obfuscation / CFG — pure in-place instruction rewriters, no new imports / TLS callbacks / PEB access. Kernel-safe by construction.
  - `VmRuntimeGenerator` — core dispatcher + handlers + bytecode are pure ALU. Two optional entry-stub blocks reach into `PEB.ImageBaseAddress` (`gs:[0x60]`): the `emit_imagebase_key_block` (already gated on `use_imagebase_key`, off for non-EXE) and the random anti-tamper / anti-emulation pick (was *on* by default, now gated by `skip_anti_tamper_checks` which `VirtualizationPass` flips true for kernel-driver targets).
  - String decryptor (`stub` / `vm` / `ephemeral`) — all three modes are pure XOR / `lock xadd` + XOR / VM-lifted XOR with `skip_anti_tamper_checks=true`. Kernel-safe. Stage 1 gate lifted.
  - Byte-scan unit test pins that the driver-path VM runtime never emits `mov rax, gs:[0x60]`, with a sanity counter-test that the pattern reappears when `use_imagebase_key` is flipped back on.
- **Stage 3 — Manual-mapped user-mode packer (in progress):**
  - Stage 3.1 (done): `--load-mode=manual` keeps `.reloc` intact (with `RELOCS_STRIPPED` still set so the loader stays out of the ciphertext) and the packer stub embeds a 116-byte post-decrypt reloc applier (`reloc_applier.cpp`). The applier computes `delta = runtime_base - preferred_base` rip-relatively, walks every `IMAGE_REL_BASED_DIR64` entry, and adds the delta in place — runs after the final cipher layer and before reprotect, so target pages are still writable. Byte-stable, unit-tested. Verified at preferred base (delta=0) — 15/15 EXE + 15/15 DLL stress in manual-map mode.
  - Stage 3.2: stress under a real manual-mapper at non-preferred base (delta != 0). Needs a kdmapper-style harness or a `LoadLibraryEx + DONT_RESOLVE_DLL_REFERENCES` style fixture to actually exercise the relocation arithmetic on a live image.
  - Stage 3.3: stub-side import resolver (Hell's Gate → `LdrLoadDll` + `LdrGetProcedureAddress`) for mappers that don't populate the IAT.
  - Stage 3.4: stub-side TLS callback invoker for mappers that skip the original callback array.
- **Stage 4 — Kernel-mode packer stub (OS-loaded):** `DriverEntry` stub, import resolution via `PsLoadedModuleList` crawl, kernel anti-debug (KUSER_SHARED_DATA / IRQL / KdDebuggerEnabled), reprotect via `MmProtectMdlSystemAddress`. Note: OS install still blocked on test-signing.
- **Stage 5 — Manual-mapped drivers (kdmapper):** Combines Stage 3's mapper-independence with Stage 4's kernel ABI. Primary deliverable per user priority.

## Deferred / Future
- **`MX_GUARD` auto-selection:** Build-time heuristic to auto-wrap sensitive regions. QoL, low protection delta.
- **`MX_GUARD` dynamic `.pdata`:** Synthesize RUNTIME_FUNCTION for guard pages → enables `throw` inside guard bodies. Medium-high complexity.
- **`MX_GUARD` PROCESS_DETACH cleanup:** `RtlRemoveVectoredExceptionHandler` on DLL unload. Needed for dynamically-unloaded DLLs (rare in injection case).
- **G5 — CFF inside handler bodies:** Low ROI (handlers are 10-50 bytes, few basic blocks).
- **Cross-platform (`IBinaryImage` refactor → Linux/ARM):** Multi-week dedicated milestone.
- **Strings S5/S6:** Split across sections, RTTI/exception handling.

## Architecture Lessons
- **Inner VM src register ≠ `rax`:** Dispatch clobbers `rax`. Use `r14`/`r15`.
- **Fetch clobbers `rflags`:** Terminal guest ALU must be the last flag-producer before tail dispatch.
- **Position independence mandatory:** rip-relative `lea` + `jmp rel8` for inner runtimes; `call rel32` for outer patches.
- **`r11` is outer VPC:** Never touch from inner VM.
- **`PEB.ImageBaseAddress` wrong for DLLs:** Use `lea rbx, [rip+0]; sub rbx, imm32` instead.
- **Inline tail dispatch > centralized:** Per-handler polymorphism defeats dedup.
- **VEH outlives DLL unload:** Runtime-guards assumes process-lifetime load; dynamically-unloaded DLLs need DETACH cleanup (deferred).
- **rel8 overflow is silent:** Use `jcc rel32` when target can be >100 bytes forward.

## Rejected (Never Revisit)
- ASLR delta-trick for ImageBase key
- Rolling key / in-place decryption for handler table
- AC flag fidelity (EFLAGS bit 18 crashes Windows user mode)
- Centralized tail dispatch trampoline
- Whole-program runtime decryption (P7) — superseded by `MX_GUARD`
