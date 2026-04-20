# MxProtector MCP — Post-MVP backlog

Items explicitly deferred from the MVP plan in [`MCP.md`](MCP.md).
Ordered roughly by priority within each section.

## VM (highest priority)

- **Symbolic handler equivalence / deduplication** — semantic classes
  via Triton + Z3. Kills cosmetic diversity; #1 post-MVP item.
  Measures resistance to symbolic execution / taint analysis — one of
  the key attacker strategies for VM deobfuscation.
- **Handler duplication / polymorphism** — same opcode served via
  multiple distinct handler bodies. Measures how well the VM resists
  "find all instances of opcode X" clustering attacks.
- **Key scheduling / inter-handler state obfuscation** — does the VM
  thread opaque state through handlers so summarising one handler
  in isolation is insufficient? Attack model: angr per-handler
  summariser that fails when state is cross-coupled.
- **MBA inside handlers** — measure simplification rate of
  per-handler expressions (msynth / SiMBA) to catch encoders that
  emit trivially simplifiable arithmetic.
- **Opaque predicates + bogus CF layered over CFF** — measure how
  often symbolic executors prune dispatcher edges correctly.
- VPC (virtual program counter) recoverability analysis.
- Handler inlining resistance (IDA aggressive-inline test).
- Dispatcher key recovery via Triton / miasm symbolic — complements
  d810 for cases d810 could not crack.

## CFF

- Per-dispatcher symbolic key recovery (Triton / miasm).

## Mutation / MBA

- qsynth as third peer in the MBA-simplification ensemble.
- Taint / backward-slice depth metric (requires miasm / angr slicer).

## Packer / runtime

- Anti-debug / anti-VM / anti-dump / TLS-callback presence audit.
  Not a score on its own — a checklist the `anti_analysis/coverage`
  benchmark consumes (see MVP P7).
- Section-level entropy trajectory (time-series diagnostic, not a
  pass/fail gate).

## Backends not yet wired

- `dynamic/{dynamorio, pin, qemu}/`
- `emulation/{qiling, triton}/`
- `symbolic/{triton, miasm, z3}/` — Z3 equivalence ground-truth lives
  here; moved out of MVP with the `nightly` tier deferral.
- `static/{ghidra, binja}/`
- `deobfuscation/cff_deobf/` (mrphrazer), `deobfuscation/devirt/`
  (VTIL, NoVMP)
- `unpacking/public/{vmattack, unlicense, scylla}/`
- `fuzzing/{aflpp, libfuzzer}/`

## Corpus

- Expand the curated corpus from the P1 seed (~10 samples) to 100+
  mini-binaries covering every protection-surface combination.
  Corpus is a fixture population question — the `fixtures/corpus/`
  directory + `corpus.py` loader arrive in MVP.

## Tiers and CI

- `nightly` tier (Z3 equivalence, full 100+ corpus, public unpacker
  baselines).
- Explicit runner entry points: `fast.py` / `slow.py` / `nightly.py`
  with per-tier budget enforcement.
- GitHub Actions matrix per tier.
- Baseline versioning via git tags instead of free-form names.
- Automatic ship-gate comment in PR body.

## Metrics maturity

- Welch's t-test for corpus-level gate decisions instead of fixed p90
  thresholds.
- Per-build variance reports (mean ± stddev) alongside single-number
  metrics.
- Per-function variance reports (worst 10% + best 10%) with explicit
  hot-function tracking (regression masking guard).
