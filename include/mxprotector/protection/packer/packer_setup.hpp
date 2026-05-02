/**
 * @file packer_setup.hpp
 * @brief Pre-stub setup helpers for the packer pipeline.
 *
 * R3.1 split-out: the packer pipeline used to bundle five distinct
 * concerns inside one ~840 LOC translation unit:
 *
 *   1. DllCharacteristics audit (CFG / FORCE_INTEGRITY policy).
 *   2. Relocation directory handling (strip vs preserve).
 *   3. Target-section selection.
 *   4. OEP-stealing.
 *   5. Stub-section injection + entry-point retarget + stolen-payload
 *      rel32 fix-ups.
 *
 * Each of these is conceptually independent of the templated
 * pipeline orchestrator (`PackerPipeline<Emitter>` in
 * `packer_pass.cpp`) — they take pure inputs and produce pure
 * outputs, with no dependency on the per-shape Emitter type.
 *
 * R3.1 moves all five into this header + a sibling source file. The
 * pipeline becomes a thin caller that wires the results together.
 *
 * Design rules:
 *   - Free functions, no class state. Anonymous-namespace helpers
 *     stay private to the source file; only the public surface is
 *     declared here.
 *   - All cross-step state flows through return values + the explicit
 *     `OepStealResult` / `PackerStubInjection` structs.
 *   - The pipeline orchestrator never reaches into PE constants
 *     directly; everything `IMAGE_*` lives behind these helpers.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/section_intent.hpp"
#include "mxprotector/protection/packer/stolen_bytes.hpp"
#include "mxprotector/protection/packer/stub_emitter.hpp"

namespace mx {

class PeImage;
class ProtectionContext;
struct SectionNameMap;

namespace packer {

/// Result of `prepare_oep_steal`: the section the real entry point
/// lives in, the entry RVA, the safe stolen-byte plan, and the bytes
/// themselves (empty if no safe prologue could be stolen, in which
/// case the stub is entered, runs its payload, and jumps straight
/// back to the unchanged entry RVA).
struct OepStealResult {
    std::size_t section_index;
    Rva         oep_rva;
    StolenPlan  plan;
    ByteBuffer  stolen_bytes;
};

/// Result of `finalize_packer_stub`.
struct PackerStubInjection {
    std::size_t pack_section_index; ///< index into ctx.pe_image().sections()
    Rva         stub_rva;           ///< RVA where the injected stub was placed
};

/// Apply `DllCharacteristics` policy to the input image.
///
/// Clears `GUARD_CF` (we add code outside the CFG bitmap) and, for
/// kernel drivers, clears `FORCE_INTEGRITY` (the driver loader
/// refuses to load a `FORCE_INTEGRITY` image whose embedded
/// signature does not validate, and our packer rewrites bytes that
/// would invalidate any pre-existing signature).
///
/// Logs one line per cleared bit; silent when the input had no
/// relevant bits set.
void apply_dll_characteristics_audit(ProtectionContext& ctx);

/// Strip base relocations from the image: clear the directory entry,
/// set `IMAGE_FILE_RELOCS_STRIPPED`, clear `DYNAMIC_BASE` in
/// `DllCharacteristics`, blank out the in-memory `.reloc` section so
/// `PeBuilder` does not re-emit it, and drop the parsed
/// `RelocationBlock` vector.
void disable_relocations(PeImage& image);

/// Pick the sections the packer must encrypt — `.text` plus any
/// MxProtector-added code sections (CFF trampolines, VM blob).
///
/// The S2 string-protection section is intentionally excluded; its
/// sticky-flag write happens at runtime and would trip the packer's
/// post-decrypt `MEM_WRITE` revoke.
[[nodiscard]] std::vector<std::size_t> collect_target_sections(
    const PeImage&        image,
    const SectionNameMap& names);

/// Pre-stub preparation: audit `DllCharacteristics`, decide the
/// `.reloc` policy by target shape, locate the section that holds
/// the real entry point, and steal a safe prologue range.
///
/// Returns `nullopt` when the image has no entry point or the entry
/// RVA falls outside every section — both are non-fatal "skip the
/// packer" signals for the caller.
///
/// @param ctx          Mutable protection context.
/// @param steal_label  Human-readable name for the entry point (e.g.
///                     `"OEP"` for EXE, `"DllMain"` for DLL,
///                     `"DriverEntry"` for SYS). Used in log lines.
[[nodiscard]] std::optional<OepStealResult> prepare_oep_steal(
    ProtectionContext& ctx,
    std::string_view   steal_label);

/// Inject the assembled stub as a fresh PE section and patch every
/// rel32 the stub depends on (the JMP back to OEP+stolen_size and
/// the CALL fix-ups inside the embedded stolen payload), then
/// retarget `AddressOfEntryPoint` at the stub.
///
/// The new section's intent is supplied by the caller: the standard
/// build uses `{code, rwx}` because the RC4 KSA scratch lives inside
/// the stub section itself.
///
/// @return `{section_index, stub_rva}` on success, or the underlying
///         section-emitter error on failure.
[[nodiscard]] MxResult<PackerStubInjection> finalize_packer_stub(
    ProtectionContext&       ctx,
    ByteBuffer&&             stub_buf,
    pe::SectionIntent        intent,
    const OepStealResult&    steal,
    const CommonStubPatches& common);

} // namespace packer
} // namespace mx
