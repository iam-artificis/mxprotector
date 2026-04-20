# Benchmark corpus

Curated mini-binaries used as the input population for defense
benchmarks. Distinct from `build_testapp/` (functional stress testing)
— benchmarks need stable, small, well-characterised inputs so metric
variance reflects defense changes rather than corpus churn.

## Layout

```
corpus/
├── corpus.json            — manifest (schema v1)
├── build.bat              — MSVC build script for unprotected inputs
├── src/
│   ├── pure_vm.cpp        — VM-heavy, no CFF surface
│   ├── pure_cff.cpp       — CFF surface, no VM markers
│   └── mixed.cpp          — realistic mix (VM + mutation + strings)
└── bin/unprotected/       — build output (gitignored, regenerable)
    ├── pure_vm.exe
    ├── pure_cff.exe
    └── mixed.exe
```

## Build

From a Visual Studio Developer Command Prompt (x64):

```cmd
cd path\to\mxprotector\mcp\fixtures\corpus
build.bat
```

The script produces `bin/unprotected/*.exe`. Benchmarks invoke the
MxProtector builder on each of these inputs at run time, so the
protected binaries always reflect the current builder state — there
is no stale "protected corpus" checked in.

### Convenience: `build_auto.bat`

For ad-hoc builds from a plain `cmd` / bash shell (without opening a
Developer Command Prompt), run `build_auto.bat` — it loads the
MSVC x64 environment via `vcvars64.bat` before dispatching to
`build.bat`. The path to `vcvars64.bat` is hard-coded for VS 2022
Community; edit `VCVARS` in that file for other editions.

## Manifest (`corpus.json`)

Schema v1. Each entry declares one of two shapes:

### Buildable entries

The classic flow — an **unprotected** source binary that every
benchmark rebuilds fresh through `mxprotector_builder` at run time
so metrics always reflect the current builder state.

| Field          | Meaning                                                   |
|----------------|-----------------------------------------------------------|
| `name`         | Stable identifier; shows up in metric evidence.           |
| `binary`       | Path to the unprotected binary, relative to corpus root.  |
| `tags`         | Protection-surface tags used by benchmark filters.        |
| `launch_args`  | Extra CLI flags the benchmark forwards when it launches  |
|                | the protected binary (e.g. `["--hold", "3"]` for pe-sieve |
|                | attach-and-scan). Optional.                               |

### Pre-protected entries

An already-protected binary preserved from an older builder — used
as "legacy" reference material for benchmarks that do not need a
sidecar (disk-entropy, strings-scan, static-file analysis). The
build step is skipped; benchmarks read the file directly.

| Field           | Meaning                                                  |
|-----------------|----------------------------------------------------------|
| `name`          | Stable identifier (conventionally prefixed `legacy_`).   |
| `pre_protected` | Path to the already-protected binary.                    |
| `pre_sidecar`   | Optional `.mxtrace.json` sidecar. Omit when unavailable. |
| `tags`          | Protection-surface tags.                                 |

At least one of `binary` / `pre_protected` must be present; both
are allowed (unprotected kept for provenance, pre-protected takes
benchmark precedence).

### Tag vocabulary

Tags describe what a benchmark is allowed to do with an entry, not
just what the source code contains:

- `vm` / `cff` / `mutation` / `strings` — the source uses the
  relevant SDK markers (and, for sidecar-dependent benchmarks, the
  entry ships a sidecar).
- `pure`  — single-surface sample (isolates one pass's contribution).
- `mixed` — multi-surface, realistic mix.
- `exe`  — PE executable (as opposed to `dll` / `sys`).
- `packer` — the benchmark may run pe-sieve (or future live-process
  scanners) against this entry. Requires the binary to stay alive
  long enough for a scanner to attach (see ``launch_args``).
  **Not applicable to pre-protected legacy entries** that exit
  immediately — they lack the `--hold` hook of the current corpus
  sources, so the pe-sieve runner cannot scan them.
- `legacy` — entry was built by an older builder version and is
  preserved verbatim for static comparison (disk-entropy, strings,
  BinDiff-against-modern). Typically paired with `exe`. No other
  capability tags because the binary is a frozen artefact.

Benchmarks filter via `corpus.with_tags("vm")` etc. A benchmark with
`corpus_tags=frozenset()` runs on the whole corpus.

## Extending

Add a new sample:

1. Drop a source file under `src/<name>.cpp`.
2. Add a `cl …` line to `build.bat` for the new source.
3. Append an entry to `corpus.json` with its path + tags.
4. Rebuild locally (`build.bat`) — the new binary lands in
   `bin/unprotected/`.

Avoid splitting samples across subdirectories; the flat layout keeps
the manifest and build script readable.

## Rebuild policy

A fresh corpus build is a reproducibility question only — benchmarks
compare a run against a baseline, both produced from the same corpus.
Corpus refreshes therefore require a coordinated baseline refresh via
the `record_baseline` MCP tool.
