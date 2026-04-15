/**
 * @file tls_callback.cpp
 * @brief P4 TLS-callback emission + existing-TLS parsing — see tls_callback.hpp.
 */

#include "mxprotector/protection/packer/tls_callback.hpp"

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/protection/packer/byte_io.hpp"
#include "mxprotector/protection/packer/rc4.hpp"

#include <cstdint>
#include <variant>

namespace mx::packer {

namespace {

/// Find the section that contains a given RVA, or nullptr if none does.
/// Used to locate the existing TLS directory's in-memory bytes and to
/// walk its callback array.
[[nodiscard]] const pe::SectionInfo*
find_section_containing_rva(const PeImage& image, Rva rva) noexcept
{
    for (const auto& sec : image.sections()) {
        if (rva >= sec.virtual_address &&
            rva <  sec.virtual_address + sec.virtual_size) {
            return &sec;
        }
    }
    return nullptr;
}

} // namespace

std::optional<ExistingTlsDirectory>
read_existing_tls_directory(const PeImage& image)
{
    Rva      tls_rva  = 0;
    uint32_t tls_size = 0;
    std::visit([&](const auto& nt) {
        if (pe::IMAGE_DIRECTORY_ENTRY_TLS < nt.OptionalHeader.NumberOfRvaAndSizes) {
            tls_rva  = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
            tls_size = nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_TLS].Size;
        }
    }, image.nt_headers());

    if (tls_rva == 0 || tls_size < 40) return std::nullopt;

    const auto* tls_sec = find_section_containing_rva(image, tls_rva);
    if (tls_sec == nullptr) return std::nullopt;

    const uint32_t off = tls_rva - tls_sec->virtual_address;
    if (static_cast<size_t>(off) + 40 > tls_sec->data.size()) return std::nullopt;

    const uint8_t* p = tls_sec->data.data() + off;
    ExistingTlsDirectory out{};
    out.start_va          = read_u64_le(p + 0x00);
    out.end_va            = read_u64_le(p + 0x08);
    out.index_va          = read_u64_le(p + 0x10);
    const uint64_t cb_va  = read_u64_le(p + 0x18);
    out.size_of_zero_fill = read_u32_le(p + 0x20);
    out.characteristics   = read_u32_le(p + 0x24);

    // Walk the existing callback array until the NULL terminator or
    // the end of whatever section it lives in. We copy the raw VAs —
    // they are correct for the preferred image base, which the packer
    // stub keeps (it strips relocations so the loaded base matches
    // the build-time preferred base).
    if (cb_va == 0) return out;  // no callbacks, but directory kept

    const auto image_base = static_cast<uint64_t>(image.image_base());
    if (cb_va < image_base) return out;  // garbage pointer — leave callbacks empty

    const auto cb_rva = static_cast<Rva>(cb_va - image_base);
    const auto* cb_sec = find_section_containing_rva(image, cb_rva);
    if (cb_sec == nullptr) return out;

    uint32_t cb_off = cb_rva - cb_sec->virtual_address;
    while (static_cast<size_t>(cb_off) + 8 <= cb_sec->data.size()) {
        const uint64_t entry = read_u64_le(cb_sec->data.data() + cb_off);
        if (entry == 0) break;
        out.callbacks.push_back(entry);
        cb_off += 8;
    }
    return out;
}

TlsCallbackEmit emit_tls_callback_body(ByteBuffer& buf,
                                       Randomizer& rng,
                                       uint32_t    layer_count)
{
    TlsCallbackEmit out{};
    out.body_offset = static_cast<uint32_t>(buf.size());

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto patch_rel8 = [&](uint32_t at) {
        const int32_t target = static_cast<int32_t>(buf.size());
        const int32_t rel8   = target - (static_cast<int32_t>(at) + 1);
        buf[at] = static_cast<uint8_t>(static_cast<int8_t>(rel8));
    };

    // cmp edx, 1
    u8(0x83); u8(0xFA); u8(0x01);
    // jne .done   — rel8 backpatched
    u8(0x75);
    const uint32_t jne_done_rel8_at = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // mov rax, gs:[0x60]   ; PEB
    u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
    u8(0x60); u8(0x00); u8(0x00); u8(0x00);
    // movzx eax, byte [rax+2]
    u8(0x0F); u8(0xB6); u8(0x40); u8(0x02);
    // test eax, eax
    u8(0x85); u8(0xC0);
    // je .done   — rel8 backpatched
    u8(0x74);
    const uint32_t je_done_rel8_at = static_cast<uint32_t>(buf.size());
    u8(0x00);

    // xor byte [rip + rel32], imm8
    //   Opcode: 80 /6 ib (XOR r/m8, imm8).
    //   ModRM: mod=00 reg=/6 rm=101 = 0x35 → rip-relative, no SIB.
    u8(0x80); u8(0x35);
    out.xor_key_rel32_offset = static_cast<uint32_t>(buf.size());
    u8(0x00); u8(0x00); u8(0x00); u8(0x00);  // rel32 placeholder
    const uint8_t mask = static_cast<uint8_t>(rng.next_range(1, 255));
    u8(mask);
    out.xor_instruction_end = static_cast<uint32_t>(buf.size());

    // .done: — back-patch the two forward rel8 branches above.
    patch_rel8(jne_done_rel8_at);
    patch_rel8(je_done_rel8_at);

    // xor eax, eax   — VOID NTAPI return, value is discarded but we
    //                  leave rax in a deterministic state.
    u8(0x31); u8(0xC0);
    // ret
    u8(0xC3);

    out.body_end_offset        = static_cast<uint32_t>(buf.size());
    out.key_byte_offset_in_key = rng.next_range(0, kKeySize - 1);
    // P2 — randomise which cipher layer's key gets corrupted. Every
    // build picks a different target, so a reverser who extracts the
    // target offset from one binary cannot predict it on the next.
    // `layer_count` is clamped to ≥1 before this call, so the upper
    // bound is always valid.
    out.key_layer_index        = rng.next_range(0, layer_count - 1);
    return out;
}

} // namespace mx::packer
