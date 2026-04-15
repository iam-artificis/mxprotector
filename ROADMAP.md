# MxProtector Roadmap

**Workflow Rule:** Validate via stress test (15/15 strong, EXE + DLL + unit tests). **Commit and push after EVERY completed item.**

## 1. Sequential Plan (sorted by value/effort)

### Tier A — cheap wins, start here
1. 📋 **G6 — Loop-based key schedules:** Wrap existing handler-table key derivation in an N-iteration loop. Symbolic execution engines (angr/KLEE/Triton) stall on loops with non-trivial trip counts. ~50 lines in `x64_vm_backend.cpp`.
2. 📋 **G3 Phase 1 — DebugObjectHandleCheck:** New `ICheck` via `NtQueryInformationProcess(ProcessDebugObjectHandle = 0x1E)`. Detects user-mode debugger attach. Direct copy of `hw_breakpoint_check` pattern. No SEH impact, works for EXE+DLL.
3. 📋 **P4 — TLS-callback entry:** Plant `IMAGE_DIRECTORY_ENTRY_TLS` pointing at a callback in `.mxpack`. Callback runs anti-debug + decrypt **before** `AddressOfEntryPoint`, defeating classic break-on-entry debuggers.

### Tier B — bigger lifts, high value
4. 📋 **G6 — Hash-based opaque predicates:** Build-time hashed constants checked at runtime; branch always taken one way but symbolic engines cannot invert the hash. New emitter, plant in entry stub or handler bodies.
5. 📋 **P2 — Multi-layer unpack:** Multiple cipher rounds in packer stub, each layer with its own key. Defeats single-pass dumping.
6. 📋 **G3 Phase 2 — VEH-based INT3 trap (gated):** Plant INT3 + chained VEH that strictly handles only own addresses (returns `CONTINUE_SEARCH` for others, preserving C++ try/catch). EXE-only, behind `--anti-tamper-veh` flag. Needs C++ exception test EXE before merge.

### Tier B — in-progress
- 📋 **P6 — Stub-self-integrity-bound cipher keys:** Each RC4 layer's effective key is `derive(base_key, stub_self_hash)` where `stub_self_hash` is an FNV-1a over the packer's own code range. Build-time and runtime compute the same hash; effective keys stored as base keys. Any stub tampering (debugger breakpoint, patched anti-debug, inline hook) changes the runtime hash → wrong effective keys → decryption produces garbage. Does NOT protect against full memory dumping AFTER successful execution — that needs P7. Honestly positioned as "static extraction + stub tampering protection".

### Tier C — defer / skip
- **P7 — Per-function runtime decryption:** True anti-dumping via VEH page-fault handlers. Each function stays encrypted at rest; accessing a page triggers a VEH that decrypts on demand and re-encrypts after execution. Very complex (requires whole-program function boundary tracking, VEH chain management, page-granular re-encryption scheduling). Multi-commit milestone, dedicated effort. **Prerequisite**: P6 (key derivation plumbing reused).
- **`--guarded-regions` flag (P6 follow-up, short-term):** Encrypt sections that aren't part of normal execution (`.rdata` string tables, `.data` globals that are immutable after init, unreached `.text` cold paths). Defends against static dumping where an attacker extracts ciphertext from an on-disk binary. One-pass encryption at build + runtime decrypt in the packer stub similar to existing `.text` handling. Estimated ~1 commit after P6.
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
- **VEH from a DLL is unsafe:** A DLL-installed VEH outlives the DLL's unload (no cleanup hook in our DllMain forwarding). Anti-tamper VEH techniques are EXE-only and must be gated on `pe_type == executable` plus an explicit opt-in flag.

## ❌ Rejected Ideas (Never Revisit)
- ASLR Delta-trick for ImageBase key.
- Rolling key for handler table.
- In-place decryption of handler table.
- AC flag fidelity (EFLAGS bit 18 crashes Windows user mode).
- Centralizing tail dispatch into a single shared trampoline (kills per-handler polymorphism).
