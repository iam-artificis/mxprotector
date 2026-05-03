/**
 * @file tls_atom_source.hpp
 * @brief Atom source for the TLS directory and the callback array
 *        it points at.
 *
 * Two atoms emitted (when present):
 *
 *   * `tls_directory` — the 40-byte `IMAGE_TLS_DIRECTORY64` block.
 *
 *   * `tls_callback_array` — null-terminated array of 8-byte VAs
 *     pointed at by `AddressOfCallBacks`. Sized
 *     `(non_null_callbacks + 1) * 8` to include the terminator.
 */

#pragma once

#include "mxprotector/pe/chaos/atom_source.hpp"

namespace mx::pe::chaos {

class TlsAtomSource final : public IAtomSource {
public:
    TlsAtomSource() noexcept = default;

    void emit_atoms(
        const PeImage& image,
        AtomTable&     out) const override;
};

} // namespace mx::pe::chaos
