# MxProtector Roadmap

**Rule:** Stress test (15/15 strong, EXE + DLL + unit tests) before every push.

## Driver / manual-map support

Priority order: **manually-mapped `.sys` → manually-mapped DLL → OS-loaded `.sys` → OS-loaded DLL**.
Exceptions / `MX_GUARD` have no ring0 analogue — guarded regions in
drivers are unsupported by design.

Build-time functional coverage is complete: `BinaryKind` + `LoadMode`
plumbed through every pass, kernel-safety audit done, manual-mapped
packer with stub-side reloc applier + `.reloc` partitioning, driver
cipher body + stub emitter, `DllCharacteristics` audit, driver-
flavoured section-name pools. See `git log` for per-stage detail.

### Remaining before the path can be declared done

- **Real-loader verification.** kdmapper end-to-end on a protected
  `.sys`; test-signed install for the OS-loaded path. Any operational
  quirk found here steers the items below.
- **Stub-side import resolver.** Hell's Gate →
  `LdrLoadDll` + `LdrGetProcedureAddress` for mappers that do not
  populate the IAT. User-mode manual-map first; a ring0 variant using
  `PsLoadedModuleList` + `RtlImageNtHeader` once user-mode stabilises.
- **Stub-side TLS callback invoker** for user-mode mappers that skip
  the original callback array (protection-completeness, not
  correctness — current behaviour is silent-no-crash).
- **Docs update:** `CLAUDE.md` section for `.sys` surface (CLI flags,
  gated passes, ring0 limitations) + short SDK note for driver
  authors. Intentionally last — docs are more accurate once real-
  loader runs surface the operational edges.

## Tooling
- **MCP defense measurement** — multi-backend MCP server measuring
  protection strength against state-of-the-art reversing tools.
  Architecture in [`MCP.md`](MCP.md), post-MVP backlog in
  [`FUTURE.md`](FUTURE.md). Status: migration commit landed; MVP
  phases P1–P10 (P1/P2/P4 complete, P3 partial, rest pending).

## Deferred / Future
- **UEFI binary support (`.efi`):** Targets like `bootmgfwx64.efi` and
  other UEFI PE32+ images. Same PE/COFF layout as drivers but with a
  distinct loader (UEFI firmware, not NT kernel), no ring0/ring3
  split, and a different runtime-services surface (no `Nt*`/`Rtl*`,
  `EFI_BOOT_SERVICES`/`EFI_RUNTIME_SERVICES` instead of ntdll). Will
  reuse the existing `BinaryKind`/`LoadMode` plumbing as a starting
  point; likely needs a new kind (e.g. `uefi_application`,
  `uefi_driver`) with its own stub palette (no Hell's Gate, no PEB
  access, no ntdll resolver — firmware-services call stubs instead).
  Scope: after the ring0 `.sys` path stabilises, because the design
  lessons there (strict-subset stub, no PEB, cipher body without
  anti-debug) will inform the UEFI stub.
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
- **Relocations can corrupt ciphertext:** Mappers that apply the `.reloc` directory will fold `delta` into bytes inside encrypted sections. Partition `.reloc` at build time: entries targeting encrypted sections get neutralised in place (`DIR64` → `ABSOLUTE`) and a private copy travels with the stub for post-decrypt application.
- **Driver stub cannot use PEB / Hell's Gate / `NtProtectVirtualMemory`:** `gs:` is KPCR in ring0. Driver cipher body is a strict subset of the user-mode one — no anti-debug probe, no ntdll resolver, no reprotect, no IAT wipe.

## Rejected (Never Revisit)
- ASLR delta-trick for ImageBase key
- Rolling key / in-place decryption for handler table
- AC flag fidelity (EFLAGS bit 18 crashes Windows user mode)
- Centralized tail dispatch trampoline
- Whole-program runtime decryption (P7) — superseded by `MX_GUARD`
