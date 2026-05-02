# MxProtector MCP — Post-MVP backlog

Deferred from MVP in [`MCP.md`](MCP.md).

## VM
- Symbolic handler equivalence / deduplication (Triton + Z3).
- Handler duplication / polymorphism (multiple bodies per opcode).
- Key scheduling / inter-handler state obfuscation.
- MBA inside handlers (msynth / SiMBA per-handler).
- Opaque predicates + bogus CF layered over CFF.
- VPC recoverability analysis.
- Handler inlining resistance (IDA aggressive-inline).
- Dispatcher key recovery via Triton / miasm.

## CFF
- Per-dispatcher symbolic key recovery (Triton / miasm).

## Mutation / MBA
- qsynth as third peer in MBA ensemble.
- Taint / backward-slice depth metric (miasm / angr).

## Packer / runtime
- Anti-debug / anti-VM / anti-dump / TLS-callback presence audit (feeds `anti_analysis/coverage`).
- Section-level entropy trajectory.

## Backends not wired
- `dynamic/{dynamorio, pin, qemu}/`
- `emulation/{qiling, triton}/`
- `symbolic/{triton, miasm, z3}/`
- `static/{ghidra, binja}/`
- `deobfuscation/cff_deobf/` (mrphrazer), `deobfuscation/devirt/` (VTIL, NoVMP)
- `unpacking/public/{vmattack, unlicense, scylla}/`
- `fuzzing/{aflpp, libfuzzer}/`

## Corpus
- Expand seed (~10) → 100+ mini-binaries covering every protection-surface combination.

## Tiers / CI
- `nightly` tier (Z3 equivalence, full 100+ corpus, public unpackers).
- Runner entry points: `fast.py` / `slow.py` / `nightly.py` with budgets.
- GitHub Actions matrix per tier.
- Baseline versioning via git tags.
- Automatic ship-gate comment in PR body.

## Metrics
- Welch's t-test for corpus gates.
- Per-build variance (mean ± stddev).
- Per-function variance (worst/best 10%) + hot-function tracking.
