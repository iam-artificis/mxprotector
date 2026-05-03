/**
 * @file vm_call_pop_trampoline_scanner.cpp
 * @brief Implementation — see header.
 *
 * The scanner uses byte-pattern matching for the fixed 9-byte prefix
 * (`call $+5; add qword [rsp], <slot>`) and the trailing `ret`. The
 * 4-byte imm32 in between is variable and is read as a signed
 * little-endian int32. We deliberately avoid Zydis here:
 *
 *   * The pattern bytes are fully constrained except for the imm32.
 *   * Zydis would still decode `add qword [rsp], imm32` as a
 *     non-relative immediate, so a fall-back mnemonic check buys
 *     nothing over a direct `memcmp`.
 *
 * To avoid false positives in middle-of-instruction byte sequences,
 * the scanner double-checks alignment by walking forward only —
 * once a match is consumed the cursor jumps past the full trampoline,
 * never re-reads its tail bytes.
 */

#include "mxprotector/pe/refmap/vm_call_pop_trampoline_scanner.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/refmap/reference.hpp"

namespace mx::pe::refmap {

namespace {

/// Total trampoline length in bytes:
///   `E8 00 00 00 00` (5) + `48 81 04 24 imm32` (8) + `C3` (1).
constexpr std::size_t kTrampolineSize = 14;

/// Offset of the imm32 slot inside the trampoline.
constexpr std::size_t kImm32Offset = 9;

/// Offset of the call's "anchor" — i.e. the byte right after the
/// 5-byte `call $+5`, equal to the value the call pushes.
constexpr std::size_t kCallAnchorOffset = 5;

/// Fixed-byte prefix of the trampoline (matches `kImm32Offset` bytes).
constexpr std::uint8_t kPrefix[kImm32Offset] = {
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x81, 0x04, 0x24,
};

/// Trailing `ret` opcode immediately after the imm32 slot.
constexpr std::uint8_t kRetOpcode = 0xC3;

/// True when the bytes at `[start, start + kTrampolineSize)` form
/// a CallPop trampoline. Reads the imm32 into `imm_out` on match.
[[nodiscard]] bool match_trampoline(
    const std::uint8_t* start,
    std::int32_t&       imm_out) noexcept
{
    if (std::memcmp(start, kPrefix, sizeof(kPrefix)) != 0) return false;
    if (start[kTrampolineSize - 1] != kRetOpcode)         return false;
    std::memcpy(&imm_out, start + kImm32Offset, sizeof(imm_out));
    return true;
}

/// Walk one code section's bytes, emitting one reference per
/// trampoline match.
void scan_section(
    ByteView        bytes,
    Rva             base_rva,
    ReferenceTable& table)
{
    if (bytes.size() < kTrampolineSize) return;

    std::size_t offset = 0;
    while (offset + kTrampolineSize <= bytes.size()) {
        std::int32_t imm = 0;
        if (!match_trampoline(bytes.data() + offset, imm)) {
            ++offset;
            continue;
        }

        // `imm == 0` would mean the trampoline jumps to its own tail
        // (self-loop). The VM's emit path never produces this; treat
        // it as a false positive on a misaligned-looking byte run
        // and decline.
        if (imm == 0) {
            ++offset;
            continue;
        }

        const Rva trampoline_rva = static_cast<Rva>(base_rva + offset);
        const Rva slot_rva       = static_cast<Rva>(
            trampoline_rva + kImm32Offset);
        const Rva anchor_rva     = static_cast<Rva>(
            trampoline_rva + kCallAnchorOffset);
        const Rva target_rva     = static_cast<Rva>(
            static_cast<std::int64_t>(anchor_rva) + imm);

        table.add(Reference{
            .location_rva = slot_rva,
            .target_rva   = target_rva,
            .width        = ReferenceWidth::byte4,
            .encoding     = ReferenceEncoding::rel32_call_pop_anchored,
            .origin       = ReferenceOrigin::vm_call_pop_trampoline,
        });

        // Skip past the entire trampoline. The first 5 bytes
        // (`call $+5`) and last byte (`ret`) cannot be the prefix
        // of another trampoline, so advancing by `kTrampolineSize`
        // is both correct and avoids overlapping false positives.
        offset += kTrampolineSize;
    }
}

} // anonymous namespace

void VmCallPopTrampolineScanner::scan(
    const PeImage&  image,
    ReferenceTable& table) const
{
    if (!image.is_64bit()) return;

    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        const auto view = ByteView{
            sec.data.data(),
            std::min(sec.data.size(),
                     static_cast<std::size_t>(sec.virtual_size))};
        scan_section(view, sec.virtual_address, table);
    }
}

} // namespace mx::pe::refmap
