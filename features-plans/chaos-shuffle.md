# Chaos-Shuffle Roadmap

Branch `b421-stability`: 10 commits, all pushed.

## Shipped

| Commit | Phase |
|---|---|
| `8f34cab` | B.4.21 — stability fix (`ReferenceOverlapFilter`, `pe::DataRegion`, `CodeGapPinAtomSource` pin-on-data) |
| `00beac0` | B.4.21 Phase B — `pe::MovableBlock` + `SectionMovableBlockAtomSource` |
| `4fd2f6a` | B.4.21 Phase C/D — 3 non-mirrored balanced encoders |
| `7fc9f81` | B.4.23 foundation — `BasicBlockAtomSource` |
| `70730f1` | B.4.22 — `add-offset-unbalanced` encoder + `pre_scanned_refs` |
| `7c85caa` | B.4.23.1 prep — `ReferenceEncoding::rva_end_exclusive` |
| `d5e9ab7` | B.4.23.1 prep — `StructureReferenceScanner` uses `rva_end_exclusive` |
| `0556a66` | B.4.23.1 prep — `sub_block_planner` shared helper refactor |
| `f6968d9` | B.4.23.1 — `PdataChainEmitter` foundation |
| **`0a60510`** | **Activation** — rel-span split filter + chain-emitter `data_regions` + new-rva overlap detection |

793/793 unit tests pass. Stress: 600/600 chaos-only, 100/100 chaos+indirect-calls.

## Stability state

| Mode | Pass rate |
|---|---|
| chaos-only (200×3) | 599/600 = 99.83% |
| chaos+indirect-calls (100) | 100/100 |
| Unit tests | 793/793 |

Residual ~0.17% on `test_string` is a NULL-r12 deref — DIFFERENT bug from the rel8 mid-instruction class fixed in `0a60510`. Capture: `_str_fail.exe` saved in `build_testapp/`. Likely a pre-existing baseline bug unrelated to sub-block shuffle.

## Remaining work

### 1. **#95 B.4.21.5 — indirect-call stub shuffle** (BIG WIN — adds movable atoms)

**Status:** Activation produces 40% pass rate (16% improvement from never-shipped). Bug is DIFFERENT class than the rel8-overflow fixed in `0a60510`.

**Symptom captured:** RIP lands at wild VA (e.g. `0x5BA3EDB8`, far outside the image). Confirmed via cdb on `_stub_sf.exe`. The CALL that targeted the stub redirected correctly; the stub computed `rax = expected target`; `xchg rax, [rsp]` + `ret` should have transferred to the function. Yet RIP went to garbage. Suspect path: function-pointer table read `jmp qword ptr [imageBase+0x16278]` returns wrong VA.

**Diff to re-apply:** ready in `IndirectCallEncoderPass::execute` — add `kStubAlignment = 4`, `padded_stub_size`, `padded_size` field on `CallSite`, replace `enc->stub_size()` with `site.padded_size` in layout/emit, add `stub_section.movable_blocks.push_back(MovableBlock{...alignment=1, kind=indirect_call_stub})` per emitted stub. Pattern is identical to the version in commit `70730f1`'s revert; reapply cleanly.

**Investigation plan:**
- Capture `_stub_sf.exe` (chaos+indirect-calls failing).
- Find the JMP/CALL that immediately preceded the wild RIP. Use cdb's `dps @rsp L20` and trace back through stack frames.
- Identify which function-pointer table the JMP read from (typically IAT at `.rdata` or LOAD_CONFIG CFG table).
- If the table contains absolute VAs (`absolute_va` encoding via `RelocAbsoluteVaScanner`), check whether chaos-shuffle remap applied to those targets correctly when the targets are stub bytes. Hypothesis: a stub's `MovableBlock` makes the stub_rva movable, but some scanner's emitted reference still uses the OLD stub_rva.
- Consider: when stubs are movable, the caller's `CALL rel32` reference target is `stub_rva`. Is the old `stub_rva` in any pin range that would prevent remapping? Check `compute_free_ranges` output with a stub-shuffle build.
- Try registering each stub's `MovableBlock` with `alignment=8` (so stubs naturally sit at 8-aligned RVAs and the LEA's disp32 byte at offset 4 lies on a 4-aligned RVA — same as shipped behaviour). If stable, the bug is in the chunk-end alignment math; if not, the bug is downstream in the patcher.

**Acceptance criterion:** chaos+indirect-calls 100/100 stable on all three test binaries.

### 2. **Byte-coverage measurement** (VERIFY THE WIN)

**Status:** B.4.23 + B.4.23.1 activation must have raised byte coverage above the prior 34-38% — sub-block shuffle now contributes multiple movable atoms per function. Not measured yet.

**Plan:**
- Run `mcp__mx-mcp__diff_defense_baseline` or equivalent on a test binary (chaos-shuffle on vs off).
- Count bytes that differ between two builds with different `MX_CHAOS_SEED` (the shuffled bytes).
- Target: ≥45 %, ideal 65-70%.
- If still below 45 %, the next lever is data-section shuffle (currently `DataSectionPinAtomSource` pins everything). Splitting data atoms at `IMAGE_REL_BASED_DIR64` slot boundaries (which the planner already pins individually via `RelocPointerAtomSource`) would let `.rdata` constants shuffle.

### 3. **#94 B.4.24 — MBA byte-noise into atom slack**

**Status:** Blocked. `BasicBlockAtomSource` emits zero-slack atoms (`slack_after = 0` everywhere). The `FallThroughJmpFiller` infrastructure (B.4.18) supports `slack_after = 5` for `JMP rel32` fall-through fixups but the basic-block source doesn't produce such atoms (the rel-span filter currently rejects splits that would need slack-after — there's no JCC-fall-through atom-source yet).

**Plan:**
- First, ship a JCC-fall-through atom-source that splits at conditional branches and emits `slack_after = 5` atoms.
- Verify `FallThroughJmpFiller` correctly fills the slack with `JMP rel32` to the moved successor.
- Then implement `MbaSlackFiller` that runs BEFORE `FallThroughJmpFiller`, fills atom slack regions WIDER than 5 bytes (e.g. 16, 32 byte slack) with random MBA-equivalent NOPs.
- Atoms with slack > 5 require widening sub-blocks at emission — the planner reserves `slack_after` bytes immediately after `size` content. Concretely: `BasicBlockAtomSource` emits `Atom { size, slack_after = 32 }`; the planner reserves `size + slack_after` bytes for the chunk; `MbaSlackFiller` writes 32 bytes of MBA noise into bytes `[size..size+slack_after)`; `FallThroughJmpFiller` (if `fall_through_to != 0`) overwrites the LAST 5 bytes with `JMP rel32`.

### 4. **Residual ~0.17% test_string failure — NULL-r12 deref**

**Status:** Pre-existing baseline. NOT the rel8-overflow class. Same pattern observed on builds before `0a60510`.

**Plan:**
- Capture multiple failing binaries; compare crash patterns.
- Likely a logic bug in mutation / obfuscation / string-protection that produces an invalid pointer occasionally.
- Investigate post-stub-shuffle work — if the same fix unblocks both, share the fix.

### 5. **Stub-shuffle interaction with the new sub-block atoms**

**Status:** With B.4.23 active, chaos+indirect-calls is 100% stable WITHOUT stub MovableBlocks. The stubs themselves stay pinned in `.callstub`; only `.text` sub-blocks shuffle. This is the conservative-and-correct state shipped at `0a60510`.

**Future:** Once #95 lands, stubs ALSO shuffle. Check that the rel-span filter logic in `sub_block_planner` extends to stubs — currently it only sees `.pdata`-listed functions. Either:
  - Extend `BasicBlockAtomSource` to also walk `.callstub`'s `movable_blocks` and apply the rel-span filter to internal stub LEAs.
  - Or accept that stubs use only `rel32` (LEA disp32) — well within int32 range — so no rel-overflow concern.

## Activation gates (env vars)

- `MX_CHAOS_SEED=<hex16>` — overrides the chaos planner seed for reproducible debugging.
- `--chaos-shuffle` — CLI flag enabling fragment shuffle.
- `--indirect-calls` — CLI flag enabling `IndirectCallEncoderPass`.

Mutation/obfuscation/string-protection use their own randomness, so the same `MX_CHAOS_SEED` does not produce identical pre-chaos buffers across builds. To make builds fully deterministic, also seed those passes — not required for the immediate roadmap but useful for byte-perfect regression bisects.

## Architecture pointers

- `pe::DataRegion` (`pe/data_region.hpp`) — byte ranges that look like code but aren't, kept out of `CodeReferenceScanner`.
- `pe::MovableBlock` (`pe/data_region.hpp`) — emitter-declared safe-to-shuffle byte runs (stubs, CFF blocks).
- `pe::PreScannedRefSlot` (`pe/pre_scanned_ref_slot.hpp`) — `(slot, target, K)` override for `rel32_with_imm_offset` non-balanced encoders.
- `pe::ExtraRvaRefSlot` (`pe/pre_scanned_ref_slot.hpp`) — generic `(slot, target, end_exclusive)` override for `rva` / `rva_end_exclusive` (used by `PdataChainEmitter` for `.mxchain` ChainInfo).
- `chaos::sub_block_planner` (`pe/chaos/sub_block_planner.hpp`) — shared sub-block split helper. `scan_function` returns `{split_candidates, rel_spans}`. `RelRefSpan` = `{lo, hi, width}` covering each `rel8`/`rel32` slot+target pair.
- `chaos::PdataChainEmitter` (`pe/chaos/pdata_chain_emitter.hpp`) — emits `.mxchain` (chained `UNWIND_INFO`) + `.mxpdat` (combined `RUNTIME_FUNCTION` array, sorted, parent EndAddress shrunk to first sub-block).

## Known invariants

- Sub-block atoms have 4-aligned start AND end RVAs (the planner pins anything else).
- The first sub-block of every function has `is_first = true` and contains the parent's `BeginAddress`.
- The last sub-block has `is_last = true` and contains the byte at `EndAddress - 1`.
- Sub-block atoms are non-overlapping and cover exactly `[fn_start_with_head, fn_end_with_tail)` for each function.
- The `RelRefSpan` filter ensures no `rel8`/`rel32` reference crosses a sub-block boundary.
- `.mxchain` and `.mxpdat` carry `DataRegion` entries covering their full extent.
- The chaos refmap appends `pre_scanned_refs` AFTER `CodeReferenceScanner` output, then `extra_rva_refs` last — patcher's last-write-wins iteration order overrides scanner-level mistakes.

## What "fully complete" means

The chaos-shuffle feature is "fully complete" when:

1. ✅ Stability ≥ 99.5% on long stress (achieved: 99.83%).
2. ⏳ Byte coverage ≥ 45% (must measure; expected to be true with B.4.23 active).
3. ⏳ Indirect-call stubs shuffle alongside `.text` sub-blocks (#95 deferred — different bug class).
4. ⏳ Atom slack carries MBA noise (B.4.24 — blocked by JCC-fall-through atom source).
5. ⏳ Residual NULL-r12 baseline bug eliminated.

Items 3-5 are independent and can be tackled in any order. Item 2 should be measured immediately to confirm the activation paid off.
