# MxProtector Roadmap

**Workflow Rule:** Validate via stress test (15/15 strong, EXE + DLL + unit tests). **Commit and push after EVERY completed item.**

## 1. Sequential Plan (sorted by value/effort)

### Tier A — cheap wins, start here
*(All previously-listed Tier A items shipped. Add new items here.)*

### Tier B — bigger lifts, high value
*(All previously-listed Tier B items shipped. Add new items here.)*

### Tier C — defer / skip
- **`MX_GUARD` auto-selection pass (runtime-guards follow-up):** Today the user marks critical regions with `MX_GUARD_BEGIN`/`END` explicitly. A build-time analyzer could scan for "sensitive" heuristic markers (string literals matching license/key patterns, calls to crypto APIs, etc.) and auto-wrap them in guard blocks. Pure quality-of-life, low protection delta. Medium complexity.
- **`MX_GUARD` dynamic `.pdata` registration (runtime-guards follow-up):** Lift the "no `throw` inside a guard body" limitation by synthesizing `RUNTIME_FUNCTION` + `UNWIND_INFO` entries for each guard page and calling `RtlAddFunctionTable` in the TLS installer. Complexity is in the unwind-info modelling (the body has no prologue; we'd need a leaf-function + chain-info chain so the unwinder walks through to the caller's frame). Medium-high complexity.
- **`MX_GUARD` DllMain PROCESS_DETACH cleanup:** For DLLs that get dynamically unloaded (uncommon but real), register a `DllMain(DLL_PROCESS_DETACH)` hook that calls `RtlRemoveVectoredExceptionHandler` before unload, and `RtlDeleteFunctionTable` if dynamic pdata was registered. Today runtime-guards on DLLs assumes the module stays loaded for the process lifetime, which is the common injection case but not universal. Low-medium complexity.
- **SYS Packer (DriverEntry stub):** Blocked on test-signing infrastructure. Kernel ABI is a full rewrite.
- **G5 — CFF inside handler bodies:** Low ROI. Handlers are 10-50 byte linear sequences with few basic blocks; effort medium, value small. Probably superseded by G6 opaque predicates.
- **P8 — Guard pages:** Marginal over existing polymorphism. Defer.
- **Phase 2 (`IBinaryImage` refactor) → Phase 3 (Linux/ARM):** Multi-week cross-platform refactor. Dedicated milestone.
- **Strings S5/S6:** Split across sections, RTTI/Exception handling. After packer polish.

## CRITICAL Architecture Lessons (Read before coding VM/Packer)
- **Inner VM `src` register is NEVER `rax`:** Dispatch loops clobber `rax`. Use `r14` (inner src) and `r15` (inner tmp).
- **Fetch clobbers `rflags`:** Outer handlers `xor/inc` destroy flags. Terminal guest ALU must be the *last* flag-producer before returning to tail dispatch.
- **`ret` preserves `rflags`:** Passed through nested calls via `ret` without push/pop.
- **Position Independence Mandatory:** Inner runtimes use ONLY rip-relative `lea` and short `jmp rel8`. Handlers use signed int32 offsets. Outer patches must be `call rel32`.
- **`r11` is Outer VPC:** Do NOT touch from inner VM.
- **`PEB.ImageBaseAddress` is wrong for DLLs:** Always returns the host EXE's base, never the DLL's own. For any in-stub computation that needs the DLL's image base, use rip-relative `lea rbx, [rip + 0]; sub rbx, imm32` instead. ASLR makes the bug intermittent (sometimes the bogus address is unmapped, sometimes it lands on host memory).
- **Per-handler dispatch polymorphism > centralization:** Inlined polymorphic tail dispatch makes byte-level dedup hard for reversers. Centralizing dispatch saves ~35 bytes/handler but lets a reverser pattern-match all handlers as identical. G5 layered trampolines on top of inlined tails instead.
- **VEH lifetime vs DLL lifetime:** A DLL-installed VEH outlives the DLL's unload — on subsequent exceptions the process jumps into freed memory. G3 Phase 2's anti-tamper INT3 trap is therefore EXE-only and gated on `pe_type == executable` plus an explicit opt-in flag. The runtime-guards subsystem (`MX_GUARD_BEGIN/END`) installs a VEH from DLLs too, but relies on the injection case where the DLL is loaded for the process lifetime. For dynamically-unloaded DLLs, a `DllMain(PROCESS_DETACH)` cleanup hook is needed (see Tier C).
- **rel8 overflow is silent:** When emitting `jne rel8` / `jcc rel8` to a forward target more than ~127 bytes away, the int32→int8 cast truncates wraps, and the branch silently jumps to a garbage offset. The bug is typically latent because single-threaded tests never take the overflowed branch — it surfaces only when real-world execution hits the `cc` condition. Use `jcc rel32` (`0F 8x rel32`) any time the destination can be more than ~100 bytes forward. Caught by the runtime-guards commit-7 polymorphism stress test that landed on a different invalid landing byte per build.

## ❌ Rejected Ideas (Never Revisit)
- ASLR Delta-trick for ImageBase key.
- Rolling key for handler table.
- In-place decryption of handler table.
- AC flag fidelity (EFLAGS bit 18 crashes Windows user mode).
- Centralizing tail dispatch into a single shared trampoline (kills per-handler polymorphism).
- Per-function whole-program runtime decryption (P7): superseded by the explicit-marker `MX_GUARD` runtime-guards subsystem. Whole-program auto-discovery was rejected as too complex for the marginal benefit over explicit markers.
