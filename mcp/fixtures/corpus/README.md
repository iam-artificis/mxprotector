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

## Manifest (`corpus.json`)

Schema v1. Each entry declares:

| Field    | Meaning                                                        |
|----------|----------------------------------------------------------------|
| `name`   | Stable identifier; shows up in metric evidence.                |
| `binary` | Path to the unprotected binary, relative to the corpus root.   |
| `tags`   | Protection-surface tags used by benchmark filters.             |

### Tag vocabulary

- `vm` / `cff` / `mutation` / `strings` — the pass this sample is
  meant to exercise.
- `pure`  — single-surface sample (isolates one pass's contribution).
- `mixed` — multi-surface, realistic mix.
- `exe`  — PE executable (as opposed to `dll` / `sys`).

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
