# MxProtector Stability Contract

MxProtector has **two layers of API surface** that move at different speeds.

1. **SDK surface** — headers under `src/sdk/include/mxprotector_sdk/` and the
   macros they define (`MX_VM_BEGIN`, `MX_STR`, `MX_CONST`, ...). Code that
   uses these macros compiles them into byte patterns that the protector
   matches at build time. **This layer is frozen** — future protector
   versions stay compatible with binaries built against today's SDK.

2. **Protector internals** — everything under `src/builder/`, every pass,
   every stub, every section name, every VM handler encoding. **This layer
   is not frozen.** Improving the protector does not require touching the
   SDK layer, and consumers do not need to rebuild their source to benefit
   from protector upgrades.

The purpose of this document is to make the boundary between the two
explicit, so that you can lock in SDK usage in your project today and
upgrade the protector independently.

---

## 1. Frozen: SDK marker macros

Defined in `src/sdk/include/mxprotector_sdk/markers.hpp`.

```cpp
MX_VM_BEGIN         MX_VM_END           // virtualization region
MX_MUTATE_BEGIN     MX_MUTATE_END       // instruction mutation region
MX_OBFUSCATE_BEGIN  MX_OBFUSCATE_END    // MBA / opaque predicate region
```

Each macro expands to a single `mov r64, imm64` instruction whose 64-bit
immediate is a magic constant:

```
 high byte : type id (0..5)
 low 7 B   : 0x00544F52505F584D  ("MX_PROT" in ASCII, little-endian)
```

**Frozen items:**

| Item                 | Value                              |
|----------------------|------------------------------------|
| `MARKER_PREFIX`      | `0x00544F52505F584DULL`            |
| `VM_BEGIN`           | type id `0`                        |
| `VM_END`             | type id `1`                        |
| `MUTATE_BEGIN`       | type id `2`                        |
| `MUTATE_END`         | type id `3`                        |
| `OBFUSCATE_BEGIN`    | type id `4`                        |
| `OBFUSCATE_END`      | type id `5`                        |
| Encoding             | `mov r64, imm64` (REX.W + B8..BF + imm64) |

The protector's marker scanner (`src/builder/analysis/marker_scanner.cpp`)
matches on exactly this pattern. Any binary containing markers of these
shapes will be scanned and processed by every future version of the
protector — the scanner is the stable ABI consumer.

**Never change without a major version bump:** the prefix, the type id
ordering, the encoding form. Adding a new marker type is fine — pick
a new id and extend the enum.

---

## 2. Frozen: other SDK facilities

- `MX_STR("...")` / `MX_WSTR(L"...")` — compile-time per-build key XOR
  string encryption. Returns `const char*` / `const wchar_t*` pointing at
  a short-lived decrypted copy. (See `src/sdk/include/mxprotector_sdk/strings.hpp`.)
- `MX_CONST(value)` — compile-time constant unfolding wrapper. Returns the
  plain value at the call site.

The **semantics** (call-site return type, side-effect profile, evaluation
order) are frozen. The **implementation** is header-only and free to change
— e.g. switching from XOR to a rolling key is a legitimate improvement that
does not break existing consumers.

---

## 3. Frozen: CLI surface

Scripts that shell out to `mxprotector_builder.exe` can rely on the following
being stable:

- `-i / --input`, `-o / --output`, `-l / --level`, `-h / --help`, `-v / --version`
- Level names: `minimal`, `standard`, `strong`, `maximum`
- Pass gates: `--no-vm`, `--no-mutation`, `--no-obfuscation`,
  `--no-cfg-flattening`, `--packer` / `--no-packer`, `--no-anti-debug`,
  `--no-anti-sandbox`, `--no-header-erasure`, `--no-strip-debug`
- `--strings={off,stub,vm}`
- `--debug-sections`, `--vm-depth=N`, `--nanomites`, `--code-interleaving`

New flags may appear in future releases. Existing flag names and meanings
will not change.

---

## 4. NOT frozen (internal)

Everything else, including:

- All passes under `src/builder/protection/`
- PE writer, section manager, section name pool
- Packer stub shape, anti-debug and anti-sandbox check set
- VM bytecode format, handler table layout, dispatcher shape
- Mutation substitution rule table, junk generator patterns
- CFG flattening dispatcher layout
- Any emitted machine code outside of the marker form

Two builds of the same source with different protector versions **will**
produce different output bytes. That is the whole point.

---

## 5. Supported targets today

Tested in end-to-end regression (unit tests + protect-and-run sample
binaries). Commits that regress this table must be reverted or fixed.

| Target         | Passes that run                                   | Command                | Notes                                                                         |
|----------------|---------------------------------------------------|------------------------|-------------------------------------------------------------------------------|
| `.exe` x64     | Mutation / Obfuscation / VM / CFF / Packer        | `-l strong`            | 240/240 stress across six test apps (40 runs each).                           |
| `.dll` x64     | Mutation / Obfuscation / VM / CFF                 | `-l strong`            | 40/40 stress on `test_dll_basic.dll`. Packer auto-skipped (exe-only stub).    |
| `.sys` x64     | *(not tested)*                                    | —                      | Packer auto-skipped on `PeType::kernel_driver`; driver signing out of scope.  |

Both auto-skips are done in `PackerPass::is_applicable` and mirrored by
`VirtualizationPass` via a `packer_will_run` gate so the imm32 table key
is used when the runtime ImageBase cannot be pinned (DLLs/drivers get
rebased by ASLR).

## 6. Known gaps

- **`--strings=stub` / `=vm`**: flag parses, config is respected by the
  fallback logic, but no pass consumes it yet. S2 pipeline stages (scanner,
  xref finder, per-string XOR encryptor, mx_str_get codegen) exist as
  library modules and have unit tests — the orchestrator pass that
  assembles the `.mxstr` section is still to be written.
- **`.dll` packer**: PackerPass auto-skips on DLL because the current
  self-unpacking stub assumes an executable entry point, not DllMain. A
  DllMain-aware stub variant is on the plan (see ROADMAP §"Sequential
  Implementation Plan").
- **`.sys` kernel driver**: not tested end-to-end. Driver signing and
  load-from-testsigning infra are prerequisites.

---

## 7. Updating your project

If you already have a project using `MX_VM_BEGIN` / `MX_STR` / etc.:

- **Upgrade the protector**: pull the repo, rebuild `mxprotector_builder`,
  re-run against your existing binaries. Your source does not need to
  change. Your baseline binaries do not need to rebuild.
- **Change the SDK headers**: generally safe as long as the marker magic
  constants are untouched. The macros may grow new fields or options.
- **Change a marker type id**: not allowed without a major version bump
  and a migration note in this file.
