/**
 * @file jmp_emit.cpp
 * @brief Implementation of the JMP rel32 helpers — see header.
 */

#include "mxprotector/protection/mutation/overflow/jmp_emit.hpp"

#include <cstring>

namespace mx::mutation::overflow {

std::int32_t compute_rel32(Rva from_rva, Rva to_rva) noexcept {
    const std::int64_t delta =
        static_cast<std::int64_t>(to_rva) -
        static_cast<std::int64_t>(from_rva + kJmpRel32Size);
    return static_cast<std::int32_t>(delta);
}

std::array<std::uint8_t, kJmpRel32Size> encode_jmp_rel32(
    Rva from_rva, Rva to_rva) noexcept
{
    std::array<std::uint8_t, kJmpRel32Size> bytes{};
    bytes[0] = 0xE9;
    const std::int32_t rel = compute_rel32(from_rva, to_rva);
    std::memcpy(&bytes[1], &rel, sizeof(rel));
    return bytes;
}

} // namespace mx::mutation::overflow
