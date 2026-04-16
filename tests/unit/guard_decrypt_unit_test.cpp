#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "mxprotector/core/raw_emitter.hpp"
#include "mxprotector/protection/guard/guard_decrypt_unit.hpp"

namespace {

using mx::RawEmitter;
using mx::guard::emit_guard_decrypt_unit;
using mx::guard::kGuardDecryptUnitSize;

[[nodiscard]] size_t find_pattern(
    const mx::ByteBuffer& buf,
    std::initializer_list<uint8_t> pattern)
{
    if (pattern.size() == 0 || pattern.size() > buf.size()) {
        return std::string::npos;
    }
    for (size_t i = 0; i + pattern.size() <= buf.size(); ++i) {
        bool match = true;
        size_t j = 0;
        for (auto b : pattern) {
            if (buf[i + j] != b) { match = false; break; }
            ++j;
        }
        if (match) return i;
    }
    return std::string::npos;
}

TEST(GuardDecryptUnit, ExactSizeMatchesConstant) {
    RawEmitter e;
    const auto result = emit_guard_decrypt_unit(e);
    EXPECT_EQ(result.size, kGuardDecryptUnitSize);
    EXPECT_EQ(e.size(), kGuardDecryptUnitSize);
}

TEST(GuardDecryptUnit, ContainsKeyReadPattern) {
    RawEmitter e;
    (void)emit_guard_decrypt_unit(e);
    const size_t pos = find_pattern(
        e.buf, {0x42, 0x0F, 0xB6, 0x44, 0x0E, 0x18});
    EXPECT_NE(pos, std::string::npos);
}

TEST(GuardDecryptUnit, ContainsHashUnmaskXor) {
    RawEmitter e;
    (void)emit_guard_decrypt_unit(e);
    const size_t pos = find_pattern(e.buf, {0x44, 0x30, 0xC0});
    EXPECT_NE(pos, std::string::npos);
}

TEST(GuardDecryptUnit, ContainsRorR8d8) {
    RawEmitter e;
    (void)emit_guard_decrypt_unit(e);
    const size_t pos = find_pattern(e.buf, {0x41, 0xC1, 0xC8, 0x08});
    EXPECT_NE(pos, std::string::npos);
}

TEST(GuardDecryptUnit, EndsWithRet) {
    RawEmitter e;
    (void)emit_guard_decrypt_unit(e);
    EXPECT_EQ(e.buf.back(), 0xC3u);
}

TEST(GuardDecryptUnit, Deterministic) {
    RawEmitter a, b;
    (void)emit_guard_decrypt_unit(a);
    (void)emit_guard_decrypt_unit(b);
    EXPECT_EQ(a.buf, b.buf);
}

TEST(GuardDecryptUnit, RollingMaskInitFromR11d) {
    RawEmitter e;
    (void)emit_guard_decrypt_unit(e);
    const size_t pos = find_pattern(e.buf, {0x45, 0x89, 0xD8});
    EXPECT_NE(pos, std::string::npos);
}

TEST(GuardDecryptUnit, OffsetIndependence) {
    RawEmitter a;
    (void)emit_guard_decrypt_unit(a);

    RawEmitter b;
    b.buf.resize(64, 0xCC);
    (void)emit_guard_decrypt_unit(b);

    ASSERT_EQ(a.size(), kGuardDecryptUnitSize);
    ASSERT_EQ(b.size(), 64 + kGuardDecryptUnitSize);
    for (size_t i = 0; i < kGuardDecryptUnitSize; ++i) {
        ASSERT_EQ(a.buf[i], b.buf[64 + i])
            << "Byte " << i << " differs with different emitter base offset";
    }
}

} // namespace
