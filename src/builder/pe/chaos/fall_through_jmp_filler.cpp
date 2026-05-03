/**
 * @file fall_through_jmp_filler.cpp
 * @brief Implementation — see header.
 *
 * The 5-byte slack window each annotated atom carries is enough for
 * exactly one `JMP rel32` (`E9 disp32`). When the planner happens to
 * keep the atom adjacent to its successor we still own the 5 bytes
 * and fill them with `NOP` (`0x90`) so the disassembly does not
 * exhibit a stray gap of unrelated bytes.
 */

#include "mxprotector/pe/chaos/fall_through_jmp_filler.hpp"

#include <cstdint>
#include <cstring>

#include "mxprotector/pe/chaos/atom.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/refmap/rva_remapper.hpp"

namespace mx::pe::chaos {

namespace {

/// Slack size we expect for fall-through atoms. Exactly enough for
/// one `JMP rel32` instruction.
constexpr std::uint32_t kJmpRel32Size = 5;

/// Locate the section that owns `rva`, returning a pointer to its
/// `data` byte or `nullptr` on miss.
[[nodiscard]] std::uint8_t* writable_byte_at(
    PeImage& image, Rva rva) noexcept
{
    for (auto& s : image.sections()) {
        if (s.data.empty()) continue;
        const auto end_va = s.virtual_address + s.virtual_size;
        if (rva < s.virtual_address || rva >= end_va) continue;
        const auto off = rva - s.virtual_address;
        if (off >= s.data.size()) return nullptr;
        return s.data.data() + off;
    }
    return nullptr;
}

/// Write five `0x90` (`NOP`) bytes starting at `rva`. Returns
/// `true` on success.
[[nodiscard]] bool write_nop5(PeImage& image, Rva rva) noexcept {
    auto* p = writable_byte_at(image, rva);
    if (p == nullptr) return false;
    // The slack is contiguous within a single section by construction
    // (the planner does not split atom slack across sections), so one
    // pointer suffices for the five-byte window.
    p[0] = p[1] = p[2] = p[3] = p[4] = 0x90;
    return true;
}

/// Write `JMP rel32` whose displacement targets `target_rva` from a
/// slot whose 5 bytes start at `slot_rva`. Returns `true` on success.
[[nodiscard]] bool write_jmp_rel32(
    PeImage& image, Rva slot_rva, Rva target_rva) noexcept
{
    auto* p = writable_byte_at(image, slot_rva);
    if (p == nullptr) return false;

    // After the 5-byte `JMP rel32`, RIP is at `slot_rva + 5`. The
    // displacement encodes the signed delta from there to the target.
    const std::int64_t disp =
        static_cast<std::int64_t>(target_rva) -
        static_cast<std::int64_t>(slot_rva + kJmpRel32Size);
    const auto rel32 = static_cast<std::int32_t>(disp);

    p[0] = 0xE9;
    std::memcpy(p + 1, &rel32, sizeof(rel32));
    return true;
}

} // anonymous namespace

std::size_t FallThroughJmpFiller::fill(
    PeImage&                            image,
    std::span<const Atom>               atoms,
    const ::mx::pe::refmap::RvaRemapper& remapper) const
{
    std::size_t filled = 0;
    for (const auto& a : atoms) {
        if (a.fall_through_to == 0) continue;
        if (a.slack_after < kJmpRel32Size) continue;

        // Slack sits immediately after the content payload.
        const Rva slack_old_rva = static_cast<Rva>(a.start_rva + a.size);

        // Where do those slack bytes land after the chaos shuffle?
        // Atoms with slack are remapped together with their content,
        // so a single remap query on the slack's first byte is the
        // correct anchor.
        const Rva slack_new_rva  = remapper.remap(slack_old_rva);
        const Rva target_new_rva = remapper.remap(a.fall_through_to);

        // When the planner kept the atom adjacent to its successor
        // we don't need a branch — but we still own the slack, so
        // emit a NOP-sled to keep the disassembly clean. (The slack
        // bytes were originally part of the atom's content range
        // upstream and may now contain stale instruction bytes from
        // before the shuffle.)
        const bool need_jmp = (slack_new_rva + kJmpRel32Size) != target_new_rva;
        const bool ok = need_jmp
            ? write_jmp_rel32(image, slack_new_rva, target_new_rva)
            : write_nop5(image, slack_new_rva);
        if (ok) ++filled;
    }
    return filled;
}

} // namespace mx::pe::chaos
