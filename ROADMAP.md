# MxProtector Roadmap

**Rule:** 15/15 strong stress test (EXE + DLL + unit tests) before every push.

## Driver / manual-map

Priority: **manually-mapped `.sys` → manually-mapped DLL → OS-loaded `.sys` → OS-loaded DLL**. Guarded regions in drivers unsupported (no ring0 analogue for `MX_GUARD`).

Build-time coverage complete: `BinaryKind` + `LoadMode` through every pass, kernel-safety audit, manually-mapped packer with stub-side reloc applier + `.reloc` partitioning, driver cipher body + stub emitter, `DllCharacteristics` audit, driver-flavoured section-name pools.

### Remaining
- **Real-loader verification.** kdmapper e2e on protected `.sys`; test-signed install for OS-loaded path.
- **Stub-side import resolver.** Hell's Gate → `LdrLoadDll` + `LdrGetProcedureAddress` (user-mode manual-map first; ring0 variant via `PsLoadedModuleList` + `RtlImageNtHeader` later).
- **Stub-side TLS callback invoker** for user-mode mappers that skip original callback array.
- **Docs:** `CLAUDE.md` section for `.sys` surface (CLI flags, gated passes, ring0 limitations) + SDK note for driver authors. Last.

## Tooling
- **MCP defense measurement.** See [`MCP.md`](MCP.md), backlog in [`FUTURE.md`](FUTURE.md). Status: migration landed; P1/P2/P4/P5/P6/P7/P8/P9/P10 complete, P3 partial.

## Deferred
- **UEFI `.efi`:** `bootmgfwx64.efi` et al. PE32+ layout, UEFI firmware loader, no ring0/ring3 split, `EFI_BOOT_SERVICES`/`EFI_RUNTIME_SERVICES` (no `Nt*`/`Rtl*`). Reuse `BinaryKind`/`LoadMode`; new kinds (`uefi_application`, `uefi_driver`), firmware-services stub palette (no Hell's Gate, no PEB, no ntdll). After `.sys` stabilises.
- **`MX_GUARD` auto-selection:** build-time heuristic for sensitive regions.
- **`MX_GUARD` dynamic `.pdata`:** synthesize RUNTIME_FUNCTION for guard pages → `throw` inside guards.
- **`MX_GUARD` PROCESS_DETACH cleanup:** `RtlRemoveVectoredExceptionHandler` on DLL unload.
- **G5 — CFF inside handler bodies.**
- **Cross-platform `IBinaryImage` refactor** → Linux/ARM.
- **Strings S5/S6:** split across sections, RTTI/exception handling.

## Architecture Lessons
- Inner VM src register ≠ `rax` (dispatch clobbers). Use `r14`/`r15`.
- Fetch clobbers `rflags`: terminal guest ALU must be last flag-producer before tail dispatch.
- Position independence mandatory: rip-relative `lea` + `jmp rel8` inner; `call rel32` outer.
- `r11` is outer VPC — never touch from inner VM.
- `PEB.ImageBaseAddress` wrong for DLLs: use `lea rbx, [rip+0]; sub rbx, imm32`.
- Inline tail dispatch > centralized (per-handler polymorphism defeats dedup).
- VEH outlives DLL unload: runtime-guards assumes process-lifetime load.
- `rel8` overflow silent: use `jcc rel32` for >100 bytes forward.
- Relocations can corrupt ciphertext: partition `.reloc` at build, neutralise entries into encrypted sections (`DIR64` → `ABSOLUTE`), ship private copy with stub for post-decrypt apply.
- Driver stub is strict subset of user-mode: no PEB / Hell's Gate / `NtProtectVirtualMemory` / anti-debug / ntdll resolver / reprotect / IAT wipe (`gs:` is KPCR).

## Rejected
- ASLR delta-trick for ImageBase key
- Rolling key / in-place decryption for handler table
- AC flag fidelity (EFLAGS bit 18 crashes user mode)
- Centralized tail dispatch trampoline
- Whole-program runtime decryption (P7) — superseded by `MX_GUARD`
