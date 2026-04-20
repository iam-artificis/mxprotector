# MxProtector Stability Contract

*Updates to the protector must NEVER require users to change their source code.*

## FROZEN (SDK Surface & CLI)
- **Magic:** `0x00544F52505F584DULL` ("MX_PROT").
- **Marker IDs:** `VM_BEGIN(0)`, `VM_END(1)`, `MUTATE_BEGIN(2)`, `MUTATE_END(3)`, `OBFUSCATE_BEGIN(4)`, `OBFUSCATE_END(5)`, `GUARD_BEGIN(6)`, `GUARD_END(7)`.
- **Encoding:** `mov r64, imm64` (REX.W + B8..BF + imm64). To add a marker: new ID, extend enum. Never change existing IDs.
- **SDK Macros:** `MX_STR`, `MX_WSTR`, `MX_CONST` — implementations can change, behavior cannot.
- **CLI:** `-i`, `-o`, `-l`, pass gates (`--no-vm`, etc.), level names (`strong`, etc.).

## NOT FROZEN (Internal Builder)
Everything in `src/builder/` is mutable. Two builds of the same source must produce completely different output bytes.

## Test-only flags (must NOT ship to production)
- `--trace-hints` — emits `<output>.mxtrace.json` with source-linked labels for the tracing MCP (`MCP_TRACING.md`). Reveals section roles and (Phase 4+) CFF/VM/guard/string metadata. Defaults to off; never enable for released builds.

## Supported Targets
| Target | Status | Notes |
|---|---|---|
| `.exe` x64 | Full | All passes. 15/15 stress + 354 unit tests. |
| `.dll` x64 | Full | DLL packer + runtime-guards (VEH from TLS callback). 15/15 stress. |
| `.sys` x64 | Untested | Blocked on test-signing. PEB-dependent code (VM, anti-tamper) needs kernel emission path. |