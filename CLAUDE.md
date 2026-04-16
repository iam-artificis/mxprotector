# MxProtector — Agent Working Notes

**Tech:** C++23, Windows PE x64. **Rule:** Test everything. Commit + push after every step.

## Build & Test
```
"C:/.../Visual Studio/.../CMake/bin/cmake.exe" --build build --config Release --target mxprotector_builder
build/src/builder/Release/mxprotector_builder.exe -i test_vm_showcase.exe -o t.exe -l strong
# Stress (15 runs):
for i in $(seq 1 15); do ../build/.../mxprotector_builder.exe -i in.exe -o t.exe -l strong >/dev/null; ./t.exe || echo "FAIL"; done
```

## Pipeline
1. `MutationPass` (100): Substitutions, junk, splitting, register reassignment.
2. `ObfuscationPass` (200): Opaque predicates, MBA, constant unfolding.
3. `VirtualizationPass` (300): Lifts `MX_VM_BEGIN/END` to VM bytecode.
4. `GuardPass` (350): Relocates `MX_GUARD_BEGIN/END` to `.mxguard`, VEH dispatch, VM-lifted decrypt.
5. `CfgFlatteningPass` (400): Dispatcher, MBA transitions.
6. `StringProtectionPass` (500): Encrypts string literals, VM-lifted decryptor stub.
7. `PackerPass` (800): Multi-section RC4, inline stub, anti-debug, IAT wipe, TLS callbacks.

## Architecture
- Passes implement `IProtectionPass`. No global state.
- `TargetInfo{os, container, arch}` — passes guard via `ctx.target().is_...()`.
- Section names: never hardcode, use `ctx.section_names()` (random per build).
- Extending VM: add handler variants in `src/builder/protection/vm/x64/`, update enum, increment `kCount`.

## Do NOT
- Revive `EncryptionPass` or `stub_main` loader — packer owns encryption.
- Hardcode `is_applicable()` without target/arch checks.
- Commit dead/unused code.