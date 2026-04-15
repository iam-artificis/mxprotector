# MxProtector Stability Contract

**Core Concept:** We have two layers. The SDK is frozen; the Builder is mutable.
*Rule: Updates to the protector must NEVER require users to change their source code.*

## 1. FROZEN (SDK Surface & CLI)
Future builder versions MUST parse and process binaries built with today's SDK.

- **Magic Marker Constants:** `0x00544F52505F584DULL` ("MX_PROT").
- **Marker IDs:** `VM_BEGIN (0)`, `VM_END (1)`, `MUTATE_BEGIN (2)`, `MUTATE_END (3)`, `OBFUSCATE_BEGIN (4)`, `OBFUSCATE_END (5)`.
- **Encoding Form:** `mov r64, imm64` (REX.W + B8..BF + imm64).
- **SDK Macros:** `MX_STR`, `MX_WSTR`, `MX_CONST` semantics (implementations can change, behavior cannot).
- **CLI Interface:** `-i`, `-o`, `-l`, pass gates (`--no-vm`, etc.), level names (`strong`, etc.).

*To add a new marker: pick a new ID and extend the enum. Never change existing IDs.*

## 2. NOT FROZEN (Internal Builder)
Everything in `src/builder/` is mutable:
- All passes, stubs, and machine code emitted (outside the marker form).
- VM bytecode formats, CFF layouts, dispatcher logic.
- Section names and PE layouts.

*Two builds of the same source must produce completely different output bytes.*

## 3. Supported Targets & Known Gaps
| Target | Status | Notes |
|---|---|---|
| `.exe` x64 | Full Support | All passes run. Validated via 15/15 stress on test_vm_basic, branch, loop, multi, showcase, stress, string + 268/268 unit tests. |
| `.dll` x64 | Full Support | DLL packer ships full decrypt pipeline through `DllFullStubEmitter` (push 11 nonvolatiles + DllMain args, gate on `reason == DLL_PROCESS_ATTACH`, decrypt + reprotect via rip-relative ImageBase). Validated 15/15 on test_dll_basic via test_dll_loader. |
| `.sys` x64 | Untested | Packer auto-skipped. Requires test-signing infra. Anti-tamper checks and VM both depend on user-mode `gs:[0x60]` PEB reads, so kernel support requires a separate emission path. |

**Known Logic Gaps:**
- `--strings=stub/vm` CLI flag parses, but the final `.mxstr` assembler orchestrator pass is not written yet.
- Anti-tamper VEH techniques (G3 Phase 2, planned) will be gated on `pe_type == executable` + explicit `--anti-tamper-veh` flag — DLLs cannot safely host VEH that outlives unload.