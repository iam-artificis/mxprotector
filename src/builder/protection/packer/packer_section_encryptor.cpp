/**
 * @file packer_section_encryptor.cpp
 * @brief P6 hash → derive → encrypt — implementation.
 *
 * Split out of `packer_pass.cpp` (R2.6). Byte-for-byte identical to
 * the inlined block that used to live inside
 * `PackerPipeline::step7_hash_and_encrypt`.
 */

#include "mxprotector/protection/packer/packer_section_encryptor.hpp"

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"
#include "mxprotector/protection/packer/rc4.hpp"
#include "mxprotector/protection/packer/stub_self_hash.hpp"

namespace mx::packer {

MxStatus hash_derive_and_encrypt(
    mx::ProtectionContext&            ctx,
    ByteBuffer&                       pack_section_data,
    uint32_t                          hash_range_end,
    uint32_t                          count_imm32_offset,
    uint32_t                          layer_count,
    const std::vector<ByteBuffer>&    layer_keys,
    std::span<const EncryptionTarget> targets)
{
    if (hash_range_end == 0 ||
        hash_range_end > pack_section_data.size())
    {
        ctx.log("PackerPass: P6 — некорректный hash_range_end, пропуск");
        return std::unexpected(
            MxError{ProtectionErrorCode::pass_failed,
                    "P6: hash_range_end_offset out of bounds"});
    }

    // (1) Patch the runtime count imm32 with the finalised byte count.
    write_i32(pack_section_data,
              count_imm32_offset,
              static_cast<int32_t>(hash_range_end));

    // (2) Compute FNV-1a over the now-finalised hashed range.
    const uint32_t stub_hash = fnv1a_32(
        ByteView{pack_section_data.data(), hash_range_end});

    ctx.log_fmt("PackerPass: P6 stub self-hash = 0x{:08X} over [0, 0x{:X})",
        stub_hash, hash_range_end);

    // (3) + (4) Derive effective keys and encrypt every target
    //           section with them. We reuse the base key buffers
    //           already written into the stub at build time — the
    //           derivation is applied to a local COPY so the stub's
    //           in-section bytes stay as base keys (which is what
    //           the runtime derivation loop consumes).
    for (uint32_t layer = 0; layer < layer_count; ++layer) {
        ByteBuffer effective = layer_keys[layer];
        derive_effective_key_in_place(
            stub_hash,
            MutableByteView{effective.data(), effective.size()});

        Rc4State rc4{};
        rc4_init(rc4,
                 ByteView{effective.data(), effective.size()},
                 /*anti_debug_bias=*/0);
        for (const auto& tgt : targets) {
            auto& sec = ctx.pe_image().sections()[tgt.image_index];
            rc4_process(rc4,
                        MutableByteView{sec.data.data(), sec.data.size()});
        }
    }

    for (const auto& tgt : targets) {
        const auto& sec = ctx.pe_image().sections()[tgt.image_index];
        ctx.log_fmt("PackerPass: зашифрована (RC4 ×{}, P6) '{}' "
                    "(RVA=0x{:08X}, {} байт)",
            layer_count, sec.name, sec.virtual_address, tgt.size);
    }
    return {};
}

} // namespace mx::packer
