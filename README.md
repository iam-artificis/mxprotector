# MxProtector

A C++23 binary protection suite for Windows PE x64.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/iam-artificis/mxprotector/actions/workflows/ci.yml/badge.svg)](https://github.com/iam-artificis/mxprotector/actions/workflows/ci.yml)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-informational.svg)](https://en.cppreference.com/w/cpp/23)

## What it does

MxProtector runs a Windows PE x64 binary through a fixed protection
pipeline: **mutation -> obfuscation -> virtualization -> guard -> CFF
-> string protection -> packer**. Mixed boolean-arithmetic (MBA)
rewriting is enabled by default across mutation and CFF transitions.

Source annotations opt individual regions and constants into stronger
transforms through a small SDK: `MX_VM_BEGIN` / `MX_VM_END` and
`MX_GUARD_BEGIN` / `MX_GUARD_END` bracket ranges for the virtual
machine and the VEH-dispatched guard, and `MX_STR` / `MX_WSTR` /
`MX_CONST` encrypt string literals and constant pools.

Windows PE x64 (`.exe` and `.dll`) is fully wired today. ELF and
ARM64 are on the roadmap and are gated at the pass level so
unsupported inputs bail out cleanly rather than crash.

## Status

Research / experimental. Not production-ready.

- `.exe` x64 -- full pipeline, 15/15 strong stress + full unit-test suite.
- `.dll` x64 -- full pipeline including DLL packer and VEH from TLS callback.
- `.sys` x64 -- untested (blocked on test-signing); build-time coverage in place.
- ELF, ARM64, UEFI -- roadmap. See [`ROADMAP.md`](ROADMAP.md).

## Requirements

- CMake >= 3.20
- A C++23 compiler: MSVC 2022, GCC 13+, or Clang 16+
- Git submodules (pulls Zydis)
- Python 3.11+ for the measurement suite in [`mcp/`](mcp/) (optional)

## Build

Clone with submodules:

```bash
git clone https://github.com/iam-artificis/mxprotector.git
cd mxprotector
git submodule update --init --recursive
```

Configure and build the protector:

```bash
cmake -S . -B build -DMXPROTECTOR_BUILD_TESTS=ON
cmake --build build --config Release --target mxprotector_builder
```

Run the unit tests (optional but recommended):

```bash
ctest --test-dir build --output-on-failure
```

## Usage

Protect a binary in one call:

```bash
./build/src/builder/Release/mxprotector_builder -i input.exe -o output.exe -l strong
```

Flags:

- `-i <path>` -- input PE (`.exe` or `.dll`).
- `-o <path>` -- output PE.
- `-l <level>` -- protection level. One of:
  - `minimal`   -- mutation only.
  - `standard`  -- mutation + obfuscation + CFF + strings.
  - `strong`    -- adds virtualization, guard, and the packer. Default target for CI stress.
  - `maximum`   -- strong with the most aggressive tunables.
- Pass gates (opt-out): `--no-mutation`, `--no-obfuscation`, `--no-vm`,
  `--no-guard`, `--no-cff`, `--no-strings`, `--no-packer`,
  `--no-mba-substitution`.

The full CLI surface is frozen; see [`STABILITY.md`](STABILITY.md).

## SDK

The SDK is a header-only set of macros consumed by the source under
protection. It is contract-frozen: updates to the protector must
never require users to change their source. Marker IDs, magic value,
encoding, and CLI names are all specified in
[`STABILITY.md`](STABILITY.md).

## Measurement suite

`mcp/` hosts **mx-mcp**, a Python MCP server that measures
MxProtector's protection strength against modern reversing tools
(angr, IDA microcode / d810, unicorn, unipacker, pe-sieve, BinDiff,
Frida, msynth, SiMBA). Install and usage are documented in
[`mcp/README.md`](mcp/README.md); the taxonomy and phase plan live in
[`MCP.md`](MCP.md).

## Documentation

- [`STABILITY.md`](STABILITY.md) -- SDK marker and CLI stability contract.
- [`MCP.md`](MCP.md) -- measurement taxonomy and phase plan.
- [`ROADMAP.md`](ROADMAP.md) -- planned features and driver work.
- [`FUTURE.md`](FUTURE.md) -- post-MVP backlog.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) -- how to propose changes.
- [`SECURITY.md`](SECURITY.md) -- vulnerability reporting.
- [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md) -- what this project is and is not for.

## Acceptable use

This is a dual-use tool. Read [`ACCEPTABLE_USE.md`](ACCEPTABLE_USE.md)
before using it.

## License

MIT -- see [`LICENSE`](LICENSE). Third-party components and their
licenses are listed in
[`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md).

## Contact

Bug reports and feature requests: open an issue on
[GitHub Issues](https://github.com/iam-artificis/mxprotector/issues).
