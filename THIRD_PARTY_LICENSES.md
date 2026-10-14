# Third-party licenses used by mxprotector

This document lists every third-party project that mxprotector links,
bundles, or invokes at runtime, together with the license each is
distributed under. It exists so downstream users can comply with those
licenses when they distribute mxprotector or a fork.

License identifiers use SPDX names. mxprotector itself is MIT (see
`LICENSE`). Where an upstream project has changed license or a
previously distributed claim was wrong, this file records the license
observed on the upstream project on 2026-09-03.

---

## Bundled (linked into `mxprotector_builder`)

Native code that becomes part of the produced `mxprotector_builder`
binary. These are the only entries whose licenses can affect
mxprotector's own distribution terms.

- **Zydis** — https://github.com/zyantific/zydis — x86/x64
  disassembler used by every code-inspection pass (mutation,
  obfuscation, virtualization, guard, CFF, packer). Included as a git
  submodule at `external/zydis` and built into `mxprotector_builder`.
  License: **MIT** (verified against upstream `LICENSE`).

- **GoogleTest** — https://github.com/google/googletest — unit test
  framework for the C++ test suite under `tests/`. Pulled at
  configure time via CMake `FetchContent` (pinned to `v1.14.0` in
  `tests/CMakeLists.txt`), and linked only into test binaries, not
  into `mxprotector_builder` itself. License: **BSD-3-Clause**.

---

## Python packages (`mcp/` measurement suite)

Runtime dependencies of the `mx-mcp` measurement server. mxprotector
does not vendor these; users install them from PyPI (or, where noted,
from GitHub) via `pip install -e ".[…]"` per `mcp/pyproject.toml`.
They run in a separate Python process; they are not linked into
`mxprotector_builder`.

### Core (always installed)

- **mcp** (Model Context Protocol Python SDK) — MCP stdio server and
  schema layer — **MIT**.
- **pydantic** — sidecar / tool-input schema validation — **MIT**.

### Optional backends

- **frida** (extra `dynamic`) — dynamic binary instrumentation used by
  the Frida-backed dynamic tools. The `frida-python` bindings are
  distributed under the **wxWindows Library Licence v3.1** (SPDX
  `wxWindows`), which is LGPL-2.0-or-later with a binary-linking
  exception; the underlying `frida-core` engine that ships in the
  wheel is itself dual-licensed (open-source / commercial) by
  Frida.re — see the upstream project for the split. mxprotector
  loads it as a normal Python dependency; nothing is statically
  linked.
- **unicorn** (extra `unicorn`) — CPU emulator used by the emulation
  backend — **GPL-2.0**.
- **angr** (extra `angr`) — symbolic-execution framework used by the
  symbolic backend — **BSD-2-Clause**.
- **unipacker** (extra `unpack`) — public unpacker used by the
  packer-robustness benchmark — **GPL-2.0** (upstream project on
  GitHub declares GPL-2.0 in its `LICENSE`; an earlier draft of this
  file recorded MIT — that was incorrect).
- **matplotlib** (extra `viz`) — chart rendering for the
  `measure_defense` / `diff_defense_baseline` tools — **matplotlib
  license** (a PSF-derived BSD-style license, SPDX `PSF-2.0`-like;
  see the upstream `LICENSE/` directory).

### Dev tooling (extra `dev`)

- **pytest** — test runner — **MIT**.
- **ruff** — linter / formatter — **MIT**.
- **mypy** — static type checker — **MIT**.

### GitHub-only Python packages

Installed by the user from git URLs, not from PyPI (see `mcp/README.md`).
Not bundled by mxprotector.

- **msynth** — https://github.com/mrphrazer/msynth — MBA / expression
  synthesis library used by the deobfuscation-robustness benchmark —
  **GPL-2.0** (upstream repository declares GPL-2.0; an earlier
  draft of this file recorded GPL-3.0 — that was incorrect).
- **SiMBA** — https://github.com/DenuvoSoftwareSolutions/SiMBA — MBA
  simplifier used by the deobfuscation-robustness benchmark —
  **GPL-3.0** (`Copyright (c) 2022 Denuvo GmbH, released under
  GPLv3`; an earlier draft of this file recorded AGPL-3.0 — that was
  incorrect).

---

## External tools (invoked at runtime, not bundled)

Executables and IDA plugins that the `mx-mcp` measurement suite
subprocesses when they are available. Users install these themselves;
mxprotector never ships or redistributes them.

- **IDA Pro** — https://hex-rays.com — headless microcode / d810 /
  pseudocode extraction — **commercial** (Hex-Rays proprietary
  license; the user must own a valid IDA license).
- **d810** — https://gitlab.com/eshard/d810 — IDA plugin used for CFF
  deobfuscation — **AGPL-3.0** (upstream GitLab project declares
  `GNU AGPLv3`; an earlier draft of this file recorded Apache-2.0 —
  that was incorrect).
- **pe-sieve** — https://github.com/hasherezade/pe-sieve — packer
  dump-resistance check — **BSD-2-Clause**.
- **BinDiff** — https://github.com/google/bindiff — two-build
  similarity diff — **Apache-2.0**.

The IDA plugin and the standalone tools are invoked as separate
processes; the measurement suite never links their code.

---

## Compliance summary

mxprotector itself is distributed under the **MIT** license (see
`LICENSE`). Nothing bundled into `mxprotector_builder` carries a
license that constrains that: Zydis (MIT) and GoogleTest (BSD-3-Clause,
test-only) are both permissive.

The GPL-family entries listed above are all **separate processes** or
**lazily loaded optional Python extras**, never statically linked into
`mxprotector_builder`:

- Runtime subprocess: `unicorn`, `d810` (AGPL-3.0, inside IDA),
  `SiMBA`, `msynth`, `unipacker`.
- Optional Python `pip install -e ".[…]"` extras that a user must
  actively opt into: same set.

Because mxprotector neither ships these tools nor executes them from
inside `mxprotector_builder`, using them through the measurement suite
does not change mxprotector's MIT status.

**However**, anyone who distributes a fork of mxprotector that
**bundles** any GPL-2.0, GPL-3.0, or AGPL-3.0 dependency in the same
distribution package (a wheel, an installer, a Docker image, a signed
release archive containing the tool binaries) must comply with the
strongest applicable copyleft — typically AGPL-3.0, which additionally
extends to network-service use. In particular, redistributing d810
alongside mxprotector, or exposing SiMBA / unipacker / msynth /
unicorn as part of a bundled product, requires releasing the combined
work under a compatible copyleft license.

If in doubt, install the copyleft tools separately on the user's
machine — the measurement suite's fail-closed self-skip contract keeps
mxprotector usable without them.
