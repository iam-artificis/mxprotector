# mx-tracing

Runtime tracer MCP server for MxProtector.

Architecture, contracts, and phase plan live in
[`../../MCP_TRACING.md`](../../MCP_TRACING.md). Do not duplicate them
here.

## Install

From this directory:

```bash
py -3 -m pip install -e ".[dev]"
```

## Run

```bash
py -3 -m mx_tracing --version
```

Claude Code auto-discovers the server via the repo-root `.mcp.json`.

## Layout

```
src/mx_tracing/
  __main__.py    # CLI entry point (Phase 0: --version / --help only)
  # Phase 2+ adds: server, session, sidecar, events, tools/, probes/,
  # invariants/, metrics/, baselines/
tests/           # pytest — populated from Phase 2 onward
fixtures/        # stable PEs for tracing — populated from Phase 3 onward
```
