/**
 * @file fnv1a_hash.hpp
 * @brief `mx::hash::IHash` implementation backed by `fnv1a_32`.
 *
 * @details Header-only — the FNV-1a-32 reference implementation is
 *          itself constexpr in `fnv1a.hpp`, so the wrapper costs
 *          nothing at runtime. The wrapper carries the running 32-bit
 *          state across `update()` calls so streaming usage works:
 *
 *              Fnv1a32Hash h;
 *              h.update(buf1);
 *              h.update(buf2);
 *              std::array<uint8_t, 4> digest;
 *              h.finalize(MutableByteView{digest.data(), 4});
 *              // digest == fnv1a_32(buf1 ++ buf2)
 *
 *          `is_cryptographic()` returns `false` — FNV-1a is a
 *          *non*-cryptographic hash. Pass-side code that needs
 *          adversary-resistant collision protection must assert this
 *          and refuse the hash, or select a different `IHash`
 *          implementation through its factory.
 */

#pragma once

#include <cstdint>
#include <cstring>

#include "mxprotector/common/hash/fnv1a.hpp"
#include "mxprotector/common/hash/hash_interface.hpp"

namespace mx::hash {

/// FNV-1a-32 implementation of `IHash`. Non-cryptographic.
class Fnv1a32Hash final : public IHash {
public:
    Fnv1a32Hash() noexcept = default;

    void reset() noexcept override {
        state_ = kFnv1aOffsetBasis;
    }

    void update(ByteView data) noexcept override {
        std::uint32_t h = state_;
        for (const std::uint8_t b : data) {
            h ^= static_cast<std::uint32_t>(b);
            h *= kFnv1aPrime;
        }
        state_ = h;
    }

    void finalize(MutableByteView out) noexcept override {
        if (out.size() < sizeof(std::uint32_t)) return;
        std::memcpy(out.data(), &state_, sizeof(std::uint32_t));
    }

    [[nodiscard]] std::size_t digest_size() const noexcept override {
        return sizeof(std::uint32_t);
    }

    [[nodiscard]] bool is_cryptographic() const noexcept override {
        return false;
    }

    [[nodiscard]] std::string_view algorithm_name() const noexcept override {
        return "FNV-1a-32";
    }

private:
    std::uint32_t state_ = kFnv1aOffsetBasis;
};

} // namespace mx::hash
