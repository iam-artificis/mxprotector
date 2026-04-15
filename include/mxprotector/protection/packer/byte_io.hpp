/**
 * @file byte_io.hpp
 * @brief Little-endian scalar read/write helpers for packer byte buffers.
 *
 * The packer assembles its stub, TLS callback body, and in-section
 * fix-up tables directly inside `ByteBuffer` objects. It needs a
 * handful of LE accessor shortcuts that operate on a buffer + offset
 * (for writes) or a raw byte pointer (for reads). These are the only
 * places we touch the bytes of an already-emitted region, so they're
 * grouped in one header rather than scattered across the sub-modules
 * that call them.
 *
 * All writers assume the destination offset is valid and in-bounds;
 * callers are responsible for that. The packer guarantees the bounds
 * because every patch offset is produced by the same emitter that
 * writes the byte, and the buffer has already been sized accordingly.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "mxprotector/core/types.hpp"

namespace mx::packer {

/**
 * @brief Write a signed 32-bit value at `offset` in little-endian.
 *
 * Used for every rel32 patch site in the packer stub — the `+0x..`
 * form in x64 `lea rip + rel32` displacements, the stolen-bytes
 * CALL rel32 fix-ups, and the `jmp rel32 → OEP+stolen_size` tail.
 */
inline void write_i32(ByteBuffer& buf, size_t offset, int32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// @brief Write an unsigned 32-bit value at `offset` in little-endian.
inline void write_u32_le(ByteBuffer& buf, size_t offset, uint32_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// @brief Write an unsigned 64-bit value at `offset` in little-endian.
///
/// Used by the P4 TLS-callback path to emit the 64-bit absolute VAs
/// inside `IMAGE_TLS_DIRECTORY64` and its callback array.
inline void write_u64_le(ByteBuffer& buf, size_t offset, uint64_t value) noexcept {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// @brief Read an unsigned 32-bit little-endian value from a raw pointer.
[[nodiscard]] inline uint32_t read_u32_le(const uint8_t* p) noexcept {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

/// @brief Read an unsigned 64-bit little-endian value from a raw pointer.
[[nodiscard]] inline uint64_t read_u64_le(const uint8_t* p) noexcept {
    uint64_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

} // namespace mx::packer
