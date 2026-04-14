# MxProtector — Agent Working Notes

**Tech Stack:** C++23, Windows PE x64 (currently). 
**Core Rule:** Test everything. **After EVERY implemented and tested step, do `git commit` and `git push`.**

## Build & Test
**Build:** Use bundled VS CMake:
`"C:/.../Visual Studio/.../CMake/bin/cmake.exe" --build build --config Release --target mxprotector_builder`

**Run/Test:**
`build/src/builder/Release/mxprotector_builder.exe -i test_vm_showcase.exe -o t.exe -l strong`

**Stress Test (15 runs):**
`for i in $(seq 1 15); do ../build/.../mxprotector_builder.exe -i in.exe -o t.exe -l strong >/dev/null; ./t.exe || echo "FAIL"; done`

## Pipeline (Execution Order)
1. `MutationPass` (100): Substitutions, junk, splitting, register reassignment.
2. `ObfuscationPass` (200): Opaque predicates, MBA, constant unfolding.
3. `VirtualizationPass` (300): Lifts `MX_VM_BEGIN/END` to VM bytecode.
4. `CfgFlatteningPass` (400): Dispatcher, MBA transitions.
5. `PackerPass` (800): Multi-section XOR, inline stub, anti-debug, IAT wipe.

## Architecture & Code Principles
- **Interfaces:** Passes must implement `IProtectionPass`. No global state side-effects.
- **Cross-Platform Foundation:** 
  - `Container axis`: `TargetInfo{os, container, arch}` (PE/ELF/Mach-O).
  - `Arch axis`: `ArchInfo` (x64/arm64). 
  - Passes must guard execution via `ctx.target().is_...()`.
- **Extending VM:** Add variants in `src/builder/protection/vm/vm_runtime_gen.cpp` (`pick_xxx_variant`), update enum, increment `kCount`.
- **Section Names:** Never hardcode. Always use `ctx.section_names()`. Randomly generated per build.

## CRITICAL: Do NOT Do This
- ❌ **Do NOT revive `EncryptionPass` or `stub_main` loader.** They are dead. Packer does the XOR + inline stub now. If direct syscalls (Hell's Gate) are needed, add them as an *option* to Packer, not a parallel pipeline.
- ❌ **Do NOT hardcode `is_applicable()`** without checking target/arch constraints.
- ❌ **Do NOT commit dead/unused code.** If it's not in the pipeline, delete it.