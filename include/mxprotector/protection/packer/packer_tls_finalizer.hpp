/**
 * @file packer_tls_finalizer.hpp
 * @brief P4 TLS callback + directory finalisation for the packer.
 *
 * Runs right after `apply_post_inject_patches` when:
 *
 *   - the .mxpack section has been placed at `stub_rva` and every
 *     byte of the stub buffer has been copied into the section;
 *   - every rel32/imm32 inside the cipher body has been resolved;
 *   - nothing has touched the TLS layout yet.
 *
 * Responsibilities (all patches are to the section bytes in place):
 *
 *   1. Point the `xor byte [rip + rel32], imm8` inside the callback
 *      body at one byte of the randomly-chosen cipher-layer key so a
 *      debugged host silently corrupts the effective key for the
 *      entire cipher cascade.
 *
 *   2. Fill the callback array in the order
 *      `[packer_cb][guard_install_cb?][user_cb_0]...[NULL]` — the
 *      packer anti-debug probe fires first, the (optional) runtime-
 *      guards VEH installer goes second so it is ready before any
 *      existing user callback can trigger a guarded path, and the
 *      input's own callbacks follow in their original order.
 *
 *   3. Fill `IMAGE_TLS_DIRECTORY64` — non-callback fields are copied
 *      from the input's existing TLS directory when present so C++
 *      `__declspec(thread)` statics keep working; otherwise
 *      `AddressOfIndex` is pointed at the scratch slot that
 *      `append_stub_artifacts` reserved inside .mxpack.
 *
 *   4. Update `DataDirectory[TLS]` in the PE optional header so the
 *      loader picks up the new directory at image load.
 *
 * Absolute VAs are safe here because PackerPass strips base
 * relocations in step1 via `disable_relocations`, so the runtime
 * image base matches the build-time preferred base.
 */

#pragma once

#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/packer/packer_stub_artifacts.hpp"

namespace mx { class ProtectionContext; }

namespace mx::packer {

/**
 * @brief Finalise the TLS callback + directory metadata inside the
 *        packer stub section.
 *
 * @param ctx           Protection context — read for the image base,
 *                      nt_headers (data directory update),
 *                      `extra_tls_callback_va` (optional guard
 *                      installer slot), and log channel.
 * @param section_data  Mutable stub section bytes, e.g.
 *                      `ctx.pe_image().sections()[pack_idx].data`.
 * @param stub_rva      Runtime RVA of `section_data[0]`.
 * @param artifacts     Stub-tail artefact offsets produced by
 *                      `append_stub_artifacts`.
 */
void finalize_tls_metadata(
    mx::ProtectionContext&   ctx,
    ByteBuffer&              section_data,
    Rva                      stub_rva,
    const StubArtifactsInfo& artifacts);

} // namespace mx::packer
