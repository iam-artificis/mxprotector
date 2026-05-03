/**
 * @file handler_table_integrity_refinalizer.cpp
 * @brief Implementation — see header.
 *
 * Pattern (32 bytes total) emitted by `x64_entry_stub.cpp`:
 *
 *   off 0  : 48 8D 1D ?? ?? ?? ??  lea  rbx, [rip + rel32]
 *   off 7  : B9       ?? ?? ?? ??  mov  ecx, total_handlers
 *   off 12 : 31 D2                  xor  edx, edx
 *   off 14 : 33 13                  xor  edx, [rbx]
 *   off 16 : 48 83 C3 04             add  rbx, 4
 *   off 20 : FF C9                   dec  ecx
 *   off 22 : 75 F4                   jnz  .loop  (rel8 = -12)
 *   off 24 : 81 F2 ?? ?? ?? ??      xor  edx, expected   <-- placeholder
 *   off 30 : 31 D0                   xor  eax, edx
 */

#include "mxprotector/pe/chaos/handler_table_integrity_refinalizer.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

constexpr std::size_t kPatternSize       = 32;
constexpr std::size_t kPlaceholderOffset = 26;  // imm32 inside `81 F2 imm32`

/// Defensive cap — `total_handlers` should be small (~14 for the inner
/// VM, a few hundred at most for the outer VM); 65 536 is a generous
/// ceiling that still terminates a runaway loop on a malformed image.
constexpr std::uint32_t kMaxHandlers = 65536;

/// Match the constant-byte mask of the integrity-check signature.
[[nodiscard]] bool match_pattern(const std::uint8_t* at) noexcept {
    static constexpr struct { std::size_t off; std::uint8_t v; } kFixed[] = {
        {0,  0x48}, {1,  0x8D}, {2,  0x1D},
        {7,  0xB9},
        {12, 0x31}, {13, 0xD2},
        {14, 0x33}, {15, 0x13},
        {16, 0x48}, {17, 0x83}, {18, 0xC3}, {19, 0x04},
        {20, 0xFF}, {21, 0xC9},
        {22, 0x75}, {23, 0xF4},
        {24, 0x81}, {25, 0xF2},
        {30, 0x31}, {31, 0xD0},
    };
    for (const auto& f : kFixed) {
        if (at[f.off] != f.v) return false;
    }
    return true;
}

[[nodiscard]] std::int32_t read_i32(
    const std::uint8_t* at, std::size_t offset) noexcept
{
    std::int32_t v = 0;
    std::memcpy(&v, at + offset, sizeof(v));
    return v;
}

[[nodiscard]] std::uint32_t read_u32(
    const std::uint8_t* at, std::size_t offset) noexcept
{
    std::uint32_t v = 0;
    std::memcpy(&v, at + offset, sizeof(v));
    return v;
}

/// Read four little-endian bytes from `image` at `rva`.
[[nodiscard]] bool read_u32_at_rva(
    const PeImage& image, Rva rva, std::uint32_t& out) noexcept
{
    const auto* sec = image.section_by_rva(rva);
    if (sec == nullptr) return false;
    const auto off = rva - sec->virtual_address;
    if (off + sizeof(std::uint32_t) > sec->data.size()) return false;
    std::memcpy(&out, sec->data.data() + off, sizeof(out));
    return true;
}

/// Recompute `expected = XOR(entry_0 .. entry_N-1)` over the
/// post-shuffle handler-table contents and patch the placeholder in
/// `sec` at `pattern_offset`. Returns `true` on success.
[[nodiscard]] bool refinalize_one(
    const PeImage& image, SectionInfo& sec, std::size_t pattern_offset)
{
    const std::uint8_t* at = sec.data.data() + pattern_offset;
    if (!match_pattern(at)) return false;

    const std::int32_t  lea_rel32      = read_i32(at, 3);
    const std::uint32_t total_handlers = read_u32(at, 8);
    if (total_handlers == 0)                return false;
    if (total_handlers > kMaxHandlers)      return false;

    // `lea rbx, [rip + rel32]` — RIP-relative anchor is `pattern_rva
    // + 7` (the byte after the 7-byte LEA).
    const Rva  pattern_rva = static_cast<Rva>(
        sec.virtual_address + pattern_offset);
    const std::int64_t handler_table_rva_signed =
        static_cast<std::int64_t>(pattern_rva) + 7 + lea_rel32;
    if (handler_table_rva_signed < 0)       return false;
    const Rva handler_table_rva = static_cast<Rva>(handler_table_rva_signed);

    // Compute the new XOR sum over the post-shuffle table contents.
    std::uint32_t xor_sum = 0;
    for (std::uint32_t i = 0; i < total_handlers; ++i) {
        std::uint32_t entry = 0;
        if (!read_u32_at_rva(image,
                             static_cast<Rva>(handler_table_rva + i * 4),
                             entry))
        {
            return false;
        }
        xor_sum ^= entry;
    }

    // Patch the imm32 placeholder so `xor edx, <expected>` flips
    // `edx` (= XOR sum of bytes the loop just walked) back to zero
    // exactly when the bytes match the post-shuffle contents.
    if (pattern_offset + kPatternSize > sec.data.size()) return false;
    std::memcpy(sec.data.data() + pattern_offset + kPlaceholderOffset,
                &xor_sum, sizeof(xor_sum));
    return true;
}

/// Walk one section's bytes, refinalising every integrity-check
/// pattern.
[[nodiscard]] std::size_t refinalize_section(
    const PeImage& image, SectionInfo& sec)
{
    if (sec.data.size() < kPatternSize) return 0;
    std::size_t count = 0;
    std::size_t off   = 0;
    while (off + kPatternSize <= sec.data.size()) {
        if (refinalize_one(image, sec, off)) {
            ++count;
            off += kPatternSize;
        } else {
            ++off;
        }
    }
    return count;
}

} // anonymous namespace

std::size_t HandlerTableIntegrityRefinalizer::refinalize(PeImage& image) const {
    if (!image.is_64bit()) return 0;

    std::size_t total = 0;
    for (auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        total += refinalize_section(image, sec);
    }
    return total;
}

} // namespace mx::pe::chaos
