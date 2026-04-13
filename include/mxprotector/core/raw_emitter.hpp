/**
 * @file raw_emitter.hpp
 * @brief Tiny byte-stream emitter for hand-rolled machine code.
 *
 * Passes that emit machine code byte-by-byte (the VM runtime generator,
 * the packer stub, the anti-emulation check assemblers) all need the same
 * trivial helper: an append-only `ByteBuffer` with `u8`/`u16`/`u32`/`u64`/
 * `bytes` shortcuts. This header extracts that helper from inside
 * `vm_runtime_gen.cpp` so it can be shared.
 *
 * It is deliberately minimal — just the shortcuts, no label resolution or
 * instruction-level abstraction. For higher-level emission see
 * `mx::analysis::X86CodeEmitter` (label-aware) or the future
 * `mx::arch::ICodeEmitter` (target-agnostic).
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx {

/**
 * @brief Append-only byte buffer with little-endian int helpers.
 *
 * Typical use:
 * @code
 *   RawEmitter e;
 *   e.u8(0x48); e.u8(0x8D); e.u8(0x1D);  // lea rbx, [rip + rel32]
 *   const auto patch_off = e.size();
 *   e.u32(0);                            // rel32 placeholder
 *   // ... later:
 *   std::memcpy(e.buf.data() + patch_off, &final_rel, 4);
 * @endcode
 */
struct RawEmitter {
    ByteBuffer buf;

    void u8(uint8_t b) { buf.push_back(b); }
    void u16(uint16_t v) {
        u8(static_cast<uint8_t>(v));
        u8(static_cast<uint8_t>(v >> 8));
    }
    void u32(uint32_t v) {
        u8(static_cast<uint8_t>(v));
        u8(static_cast<uint8_t>(v >> 8));
        u8(static_cast<uint8_t>(v >> 16));
        u8(static_cast<uint8_t>(v >> 24));
    }
    void u64(uint64_t v) {
        u32(static_cast<uint32_t>(v));
        u32(static_cast<uint32_t>(v >> 32));
    }
    void bytes(ByteView data) {
        buf.insert(buf.end(), data.begin(), data.end());
    }

    [[nodiscard]] size_t size() const noexcept { return buf.size(); }
};

} // namespace mx
