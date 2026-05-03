/**
 * @file self_crc_refinalizer.cpp
 * @brief Implementation — see header.
 *
 * Pattern (36 bytes total) emitted by `self_crc_check.cpp`:
 *
 *   off 0  : 48 8D 35 ?? ?? ?? ??   lea  rsi, [rip + rel32]
 *   off 7  : B9       ?? ?? ?? ??   mov  ecx, len32
 *   off 12 : B8 FF FF FF FF         mov  eax, 0xFFFFFFFF
 *   off 17 : F2 0F 38 F0 06         crc32 eax, byte ptr [rsi]
 *   off 22 : 48 FF C6                inc  rsi
 *   off 25 : FF C9                   dec  ecx
 *   off 27 : 75 F4                   jnz  -12
 *   off 29 : F7 D0                   not  eax
 *   off 31 : 3D ?? ?? ?? ??         cmp  eax, imm32   <-- placeholder
 *
 * The signature is unambiguous in 64-bit code — every byte is
 * fixed except the two embedded immediates (`rel32`, `len32`) and
 * the trailing 4-byte placeholder.
 */

#include "mxprotector/pe/chaos/self_crc_refinalizer.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"

namespace mx::pe::chaos {

namespace {

/// Total size of the self-CRC pattern.
constexpr std::size_t kPatternSize = 36;

/// Offset of the first byte of the placeholder slot inside the
/// pattern.
constexpr std::size_t kPlaceholderOffset = 32;

/// CRC32C software reference — must match the polynomial used by
/// the runtime `crc32 eax, byte ptr [reg]` (Castagnoli, reflected).
[[nodiscard]] constexpr std::uint32_t crc32c_update(
    std::uint32_t crc, std::uint8_t byte) noexcept
{
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
        crc = (crc >> 1) ^ ((crc & 1u) ? 0x82F63B78u : 0u);
    }
    return crc;
}

/// Walk a `length`-byte range at `start_offset` in `bytes`, returning
/// the CRC32C with the standard `init = 0xFFFFFFFF, final XOR =
/// 0xFFFFFFFF` convention. Out-of-bounds reads return `nullopt`.
[[nodiscard]] bool compute_crc32c(
    const std::uint8_t* bytes,
    std::size_t         buffer_size,
    std::size_t         start_offset,
    std::size_t         length,
    std::uint32_t&      out)
{
    if (start_offset >= buffer_size)              return false;
    if (start_offset + length > buffer_size)      return false;

    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < length; ++i) {
        crc = crc32c_update(crc, bytes[start_offset + i]);
    }
    out = ~crc;
    return true;
}

/// `true` when the bytes at `[at, at + kPatternSize)` form the
/// self-CRC signature. The two variable-width fields (rel32 at +3
/// and len32 at +8) are passed through; the rest of the bytes must
/// match the constant template.
[[nodiscard]] bool match_pattern(const std::uint8_t* at) noexcept {
    static constexpr struct { std::size_t off; std::uint8_t v; } kFixed[] = {
        {0,  0x48}, {1,  0x8D}, {2,  0x35},
        {7,  0xB9},
        {12, 0xB8}, {13, 0xFF}, {14, 0xFF}, {15, 0xFF}, {16, 0xFF},
        {17, 0xF2}, {18, 0x0F}, {19, 0x38}, {20, 0xF0}, {21, 0x06},
        {22, 0x48}, {23, 0xFF}, {24, 0xC6},
        {25, 0xFF}, {26, 0xC9},
        {27, 0x75}, {28, 0xF4},
        {29, 0xF7}, {30, 0xD0},
        {31, 0x3D},
    };
    for (const auto& f : kFixed) {
        if (at[f.off] != f.v) return false;
    }
    return true;
}

/// Read four little-endian bytes at `at + offset` as a signed int32.
[[nodiscard]] std::int32_t read_i32(
    const std::uint8_t* at, std::size_t offset) noexcept
{
    std::int32_t v = 0;
    std::memcpy(&v, at + offset, sizeof(v));
    return v;
}

/// Read four little-endian bytes at `at + offset` as an unsigned
/// int32.
[[nodiscard]] std::uint32_t read_u32(
    const std::uint8_t* at, std::size_t offset) noexcept
{
    std::uint32_t v = 0;
    std::memcpy(&v, at + offset, sizeof(v));
    return v;
}

/// Try to refinalise a single self-CRC pattern at offset `at_offset`
/// inside `sec`. Returns `true` on success.
///
/// The CRC range start RVA is `lea_after_rva + rel32` (standard
/// rip-relative semantics). Both the range and the placeholder must
/// live inside the section's data buffer; cross-section reads are
/// rejected.
[[nodiscard]] bool refinalize_one(
    SectionInfo& sec, std::size_t at_offset)
{
    const std::uint8_t* at = sec.data.data() + at_offset;
    if (!match_pattern(at)) return false;

    const std::int32_t  lea_rel32 = read_i32(at, 3);
    const std::uint32_t length    = read_u32(at, 8);
    if (length == 0) return false;

    // `lea rsi, [rip + rel32]` — the RIP-relative anchor is the
    // byte right after the 7-byte lea, which equals
    // `pattern_rva + 7`. Convert to a section offset.
    const std::int64_t lea_anchor_off =
        static_cast<std::int64_t>(at_offset) + 7;
    const std::int64_t range_start_off =
        lea_anchor_off + lea_rel32;
    if (range_start_off < 0) return false;

    std::uint32_t crc = 0;
    if (!compute_crc32c(
            sec.data.data(), sec.data.size(),
            static_cast<std::size_t>(range_start_off),
            length, crc))
    {
        return false;
    }

    // Patch the imm32 placeholder at +32.
    if (at_offset + kPatternSize > sec.data.size()) return false;
    std::memcpy(sec.data.data() + at_offset + kPlaceholderOffset,
                &crc, sizeof(crc));
    return true;
}

/// Walk one section's bytes, refinalising every self-CRC pattern.
[[nodiscard]] std::size_t refinalize_section(SectionInfo& sec) {
    if (sec.data.size() < kPatternSize) return 0;
    std::size_t count = 0;
    std::size_t off   = 0;
    while (off + kPatternSize <= sec.data.size()) {
        if (refinalize_one(sec, off)) {
            ++count;
            off += kPatternSize;
        } else {
            ++off;
        }
    }
    return count;
}

} // anonymous namespace

std::size_t SelfCrcRefinalizer::refinalize(PeImage& image) const {
    if (!image.is_64bit()) return 0;

    std::size_t total = 0;
    for (auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        total += refinalize_section(sec);
    }
    return total;
}

} // namespace mx::pe::chaos
