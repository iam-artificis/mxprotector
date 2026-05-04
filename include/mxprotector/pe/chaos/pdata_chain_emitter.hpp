/**
 * @file pdata_chain_emitter.hpp
 * @brief Emit chained `RUNTIME_FUNCTION` entries for every sub-block
 *        produced by `BasicBlockAtomSource` (B.4.23.1).
 *
 * **Why this emitter exists.**
 *
 * Once `BasicBlockAtomSource` splits a function into N sub-blocks
 * and the chaos shuffle relocates each independently, the original
 * `RUNTIME_FUNCTION` entry — `BeginAddress=fn_start, EndAddress=
 * fn_end` — no longer describes a contiguous range. The Windows
 * SEH unwinder (`RtlpLookupRuntimeFunctionEntry`) walks `.pdata`
 * sorted by `BeginAddress` and binary-searches `BeginAddress <=
 * RIP < EndAddress`. Without per-sub-block coverage, every RIP in
 * any non-first sub-block falls outside the only entry's patched
 * `[BeginAddress, EndAddress)` window — the unwinder fails to
 * dispatch, and even normal-execution stack walks (CRT init,
 * RtlVirtualUnwind in startup) crash the process.
 *
 * `PdataChainEmitter` produces the missing coverage. For each
 * non-first sub-block it:
 *
 *   1. Builds a 16-byte chained `UNWIND_INFO` (header with
 *      `UNW_FLAG_CHAININFO=4`, zero unwind codes, ChainInfo trailer
 *      pointing to the parent's first sub-block + parent's
 *      `UnwindInfoAddress`). The unwinder follows the chain to
 *      replay the parent's prologue codes when unwinding.
 *
 *   2. Builds a 12-byte `RUNTIME_FUNCTION`
 *      `{BeginAddress=sub_start, EndAddress=sub_end,
 *      UnwindInfoAddress=chained_uwi_rva}`.
 *
 * The original .pdata entry's `EndAddress` is **shrunk** to the
 * first sub-block's end — covering only that sub-block. Every
 * later sub-block is covered by its chained entry. After sort by
 * `BeginAddress`, the unified `.mxpdat` directory has one entry
 * per sub-block, each pointing the unwinder to the right unwind
 * codes via the chained ChainInfo path.
 *
 * The emitter creates two new sections:
 *
 *   * `.mxchain` — read-only data, holds the 16-byte chained
 *     `UNWIND_INFO` blobs concatenated.
 *   * `.mxpdat` — read-only data, holds the combined
 *     `RUNTIME_FUNCTION` array (original entries with shrunk
 *     `EndAddress` + chained entries, sorted).
 *
 * `IMAGE_DIRECTORY_ENTRY_EXCEPTION` is rewritten to point at
 * `.mxpdat`. The original `.pdata` bytes remain in the image but
 * are no longer the directory's storage — they become orphaned
 * data the loader does not read.
 *
 * SOLID:
 *   * SRP — exactly one task: emit chained .pdata coverage. The
 *     sub-block split itself lives in `sub_block_planner.{hpp,cpp}`.
 *
 *   * OCP — the emitter consumes the planner's `SubBlock` list and
 *     the `SectionEmitter` for adding sections; no other layer
 *     needs to know it ran. New sub-block sources (e.g. the future
 *     basic-block JCC splitter) plug in by extending the planner;
 *     this emitter picks them up automatically.
 *
 * Threading: stateless. One emitter per build.
 */

#pragma once

#include <cstddef>

namespace mx {
class PeImage;
} // namespace mx

namespace mx::pe {
class SectionEmitter;
} // namespace mx::pe

namespace mx::pe::chaos {

/**
 * @brief Chained-`.pdata` emitter — see file header.
 */
class PdataChainEmitter {
public:
    PdataChainEmitter() = default;

    /**
     * @brief Compute sub-blocks via `plan_sub_blocks`, build the
     *        `.mxchain` and `.mxpdat` sections, redirect the
     *        `IMAGE_DIRECTORY_ENTRY_EXCEPTION`.
     *
     * @return The number of CHAINED entries appended (i.e. number
     *         of non-first sub-blocks). Zero when no function had a
     *         usable split, in which case the image is left
     *         unchanged.
     *
     * No-op when:
     *   * The image is not 64-bit.
     *   * `.pdata` is missing or empty.
     *   * The planner returns empty (no functions).
     *   * Adding either new section fails.
     *
     * Failures past the first emitted section are LEAKY — the
     * partially-added section is left in place. The pass MUST run
     * before chaos finalisation merges sections, so the unified
     * section will absorb the orphaned bytes and the image stays
     * loadable.
     */
    [[nodiscard]] std::size_t emit(
        ::mx::PeImage&        image,
        ::mx::pe::SectionEmitter& emitter) const;
};

} // namespace mx::pe::chaos
