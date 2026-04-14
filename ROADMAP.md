# MxProtector Roadmap

**Workflow Rule:** Do items sequentially. Validate via stress test (90/90 strong). **Commit and push after EVERY completed item.**

## 1. Sequential Implementation Plan (DO IN ORDER)
1. ⏳ **DLL Packer (DllMain stub):** Current packer skips `.dll`. Implement `DLL_PROCESS_ATTACH` decrypt loop -> call real DllMain. Preserve export table + IAT.
2. 📋 **SYS Packer (DriverEntry stub):** Same as DLL but for kernel-mode ABI (blocked on test-signing infra).
3. 📋 **P5 Packer Hashing:** Replace `LoadLibrary/GetProcAddress` in stub with DJB2/FNV-1a hash resolution to kill `strings`.
4. 📋 **P2/P4/P6/P7/P8 Packer Polish:** Multi-layer unpack, TLS-callback entry, CFI in decrypt, header stripping, guard pages.
5. 📋 **G5 Call Graph Obfuscation:** Trampolined dispatch, flattened handler bodies (CFF inside handlers), interleaving.
6. 📋 **G6 Symbolic-Execution Hardening:** Hash-based opaque predicates, memory-dependent CFG, loop-based key schedules.
7. 📋 **G3 Anti-Tamper:** Thread context poisoning, VEH-integrity traps.

*(Note: G2 Nested VM and G4 Bytecode Obfuscation are fully shipped. Do not touch unless fixing bugs).*

## 2. Cross-Platform & String Plans
- **Phase 2 (Containers):** Extract PE logic into `IBinaryImage` / `IBinaryImageParser`.
- **Phase 3 (Linux/ARM):** `ElfParser/Builder`, `Arm64CodeEmitter`, `Arm64VmBackend`.
- **Strings:** Split across sections (S5), handle RTTI/Exceptions (S6). Implement `--strings=stub/vm` orchestrator.

## CRITICAL Architecture Lessons (Read before coding VM/Packer)
- **Inner VM `src` register is NEVER `rax`:** Dispatch loops clobber `rax`. Use `r14` (inner src) and `r15` (inner tmp).
- **Fetch clobbers `rflags`:** Outer handlers `xor/inc` destroy flags. Terminal guest ALU must be the *last* flag-producer before returning to tail dispatch.
- **`ret` preserves `rflags`:** Passed through nested calls via `ret` without push/pop.
- **Position Independence Mandatory:** Inner runtimes use ONLY rip-relative `lea` and short `jmp rel8`. Handlers use signed int32 offsets. Outer patches must be `call rel32`.
- **`r11` is Outer VPC:** Do NOT touch from inner VM.

## ❌ Rejected Ideas (Never Revisit)
- ASLR Delta-trick for ImageBase key.
- Rolling key for handler table.
- In-place decryption of handler table.
- AC flag fidelity (EFLAGS bit 18 crashes Windows user mode).