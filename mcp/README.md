# mx-mcp

MCP server that measures MxProtector's protection strength against
state-of-the-art reversing tools. Architecture, benchmark spec, and
phase plan live in [`../MCP.md`](../MCP.md). Post-MVP backlog in
[`../FUTURE.md`](../FUTURE.md).

## Install

### Core (always needed)

```bash
cd mcp
py -3 -m pip install -e ".[dev]"
```

Installs the MCP stdio server, pydantic sidecar schema, Frida DBI
backend, and pytest/ruff/mypy for development.

### Optional backends (per-category, added as phases land)

```bash
py -3 -m pip install -e ".[unicorn]"        # P3 — emulation
py -3 -m pip install -e ".[angr]"           # P4 — symbolic
py -3 -m pip install -e ".[unpack]"         # P6 — unipacker
py -3 -m pip install -e ".[full,dev]"       # everything pip-installable
```

### GitHub-only Python packages

Some backends ship from source (not on PyPI). Install individually:

```bash
py -3 -m pip install "msynth @ git+https://github.com/mrphrazer/msynth.git"
py -3 -m pip install "simba  @ git+https://github.com/DenuvoSoftwareSolutions/SiMBA.git"
```

### External binaries (configured via env vars)

| Tool     | Purpose                                  | Env var                | Default |
|----------|------------------------------------------|------------------------|---------|
| IDA Pro  | Headless microcode / d810 / pseudocode   | `MX_MCP_IDA_PATH`      | `idat.exe` on `PATH` |
| pe-sieve | Packer dump-resistance check             | `MX_MCP_PE_SIEVE_PATH` | `pe-sieve.exe` on `PATH` |
| BinDiff  | Two-build similarity diff                | `MX_MCP_BINDIFF_PATH`  | `bindiff.exe` on `PATH` |
| d810     | CFF deobfuscation (IDA plugin)           | Install to `<IDA>/plugins/` | — |

Tools self-skip with a readable message when their binary is missing;
the rest of the server stays up.

## Run

```bash
py -3 -m mx_mcp --version
py -3 -m mx_mcp serve          # MCP stdio loop
```

Claude Code auto-discovers the server via the repo-root `.mcp.json`.

## Debug

```bash
MX_MCP_DEBUG=1 py -3 -m mx_mcp serve    # DEBUG logging on stderr
```

## Layout

See [`../MCP.md`](../MCP.md) for the full taxonomy tree. Short form:

```
src/mx_mcp/
  common/        — ABCs, sidecar, events, pe_reader, logging
  dynamic/frida/ — Session, JS probes, Frida-backed tools
  static/        — sidecar readers, IDA scripts (phases)
  invariants/    — protection invariants (oep_is_stub, packer_decrypted)
  tools/         — top-level MCP tools (verify_protection_invariants)
  server.py      — stdio server + tool registry glue
```

## Tests

```bash
py -3 -m pytest --collect-only    # discovery smoke check
py -3 -m pytest                    # full suite (requires built builder +
                                   #  build_testapp/test_vm_showcase.exe)
```

The `traced_fixture` session fixture invokes `mxprotector_builder.exe`
from `../build/src/builder/Release/`. If the builder is not built, those
tests are skipped rather than failed.
