# Benchmark corpus

Curated mini-binaries used by `mcp/src/mx_mcp/benchmarks/` as the
input population for defense metrics. Distinct from `build_testapp/`
(functional stress testing) — benchmarks need a stable, small,
well-characterised set so that metric variance reflects defense
changes rather than corpus churn.

## Contract

Each entry covers a specific protection surface so benchmarks can
gate per-surface regressions without running the full pipeline:

- `pure_vm_*.exe`        — VM-heavy, minimal non-VM code
- `pure_cff_*.exe`       — CFF-dense without VM
- `mixed_*.exe`          — realistic mix (strong-level preset)
- `tls_heavy_*.exe`      — many TLS callbacks (early-entry metrics)
- `seh_*.exe`            — SEH / C++ exceptions (VEH interaction)
- `dll_*.dll`            — dynamic library variant
- `driver_*.sys`         — kernel driver variant (when ring0 gated)

## Population

Empty at migration (this commit). Populated in the "Benchmark infra"
phase (P1 per `MCP.md`) using small source files under
`tests/testapp/` or new fixture sources. Each binary lives in git
alongside its `.mxtrace.json` sidecar (both regenerated when the
corpus is refreshed).

## Rebuild

A fresh corpus build is a reproducibility question only — the
benchmarks compare a run against a baseline, both produced from the
same corpus. Corpus refreshes therefore require a coordinated
baseline refresh via `record_baseline`.
