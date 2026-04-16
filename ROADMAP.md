# MxProtector Roadmap

**Rule:** Stress test (15/15 strong, EXE + DLL + unit tests) before every push.

## Deferred / Future
- **`MX_GUARD` auto-selection:** Build-time heuristic to auto-wrap sensitive regions. QoL, low protection delta.
- **`MX_GUARD` dynamic `.pdata`:** Synthesize RUNTIME_FUNCTION for guard pages → enables `throw` inside guard bodies. Medium-high complexity.
- **`MX_GUARD` PROCESS_DETACH cleanup:** `RtlRemoveVectoredExceptionHandler` on DLL unload. Needed for dynamically-unloaded DLLs (rare in injection case).
- **SYS Packer:** Blocked on test-signing. Kernel ABI is a full rewrite.
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
