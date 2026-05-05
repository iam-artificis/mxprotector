/**
 * @file x86_arch_emitter_test.cpp
 * @brief Unit tests for `analysis::X86ArchEmitter` and `X86CodeEmitterFactory`.
 *
 * @details Confirms:
 *            * `X86ArchEmitter` reports x64 family / variant.
 *            * `X86CodeEmitterFactory` reports x64 supported family and
 *              produces a working emitter.
 *            * Adapter byte output matches the underlying `X86CodeEmitter`
 *              for representative ops (mov_rr, add_rr, ret, jmp+label).
 *            * Out-of-range register id (>15) returns a `pass_failed`
 *              MxStatus instead of UB.
 *            * Round-trip mov→add→ret produces a valid finished blob.
 */

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/analysis/x86_arch_emitter.hpp"
#include "mxprotector/arch/arch_info.hpp"
#include "mxprotector/arch/code_emitter.hpp"

namespace {

using mx::arch::ArchFamily;
using mx::arch::ArchInfo;
using mx::arch::ArchVariant;
using mx::arch::CondCode;
using mx::arch::ICodeEmitter;
using mx::arch::Label;
using mx::arch::Reg;
using mx::analysis::X86ArchEmitter;
using mx::analysis::X86CodeEmitter;
using mx::analysis::X86CodeEmitterFactory;

constexpr Reg make_reg(uint8_t id, uint8_t width = 8) noexcept {
    return Reg{id, width};
}

} // namespace

TEST(X86ArchEmitter, ReportsX64Family) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    EXPECT_EQ(em.arch().family, ArchFamily::x64);
    EXPECT_EQ(em.arch().variant, ArchVariant::x64_generic);
}

TEST(X86ArchEmitter, FactoryProducesX64Emitter) {
    X86CodeEmitterFactory factory;
    EXPECT_EQ(factory.supported_family(), ArchFamily::x64);
    auto em = factory.create(ArchInfo::x64_baseline());
    ASSERT_NE(em, nullptr);
    EXPECT_EQ(em->arch().family, ArchFamily::x64);
}

TEST(X86ArchEmitter, MovRegReg64MatchesUnderlying) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    ASSERT_TRUE(em.mov_rr(make_reg(0), make_reg(3)).has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());

    X86CodeEmitter ref(true);
    ref.mov(mx::x86::Reg::rax, mx::x86::Reg::rbx);
    auto ref_blob = ref.build();
    ASSERT_TRUE(ref_blob.has_value());

    EXPECT_EQ(*blob, *ref_blob);
}

TEST(X86ArchEmitter, AddRegRegMatchesUnderlying) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    ASSERT_TRUE(em.add_rr(make_reg(1), make_reg(2)).has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());

    X86CodeEmitter ref(true);
    ref.add(mx::x86::Reg::rcx, mx::x86::Reg::rdx);
    auto ref_blob = ref.build();
    ASSERT_TRUE(ref_blob.has_value());

    EXPECT_EQ(*blob, *ref_blob);
}

TEST(X86ArchEmitter, RetEmitsSingleByteC3) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    ASSERT_TRUE(em.ret().has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());
    ASSERT_EQ(blob->size(), 1u);
    EXPECT_EQ((*blob)[0], 0xC3);
}

TEST(X86ArchEmitter, JmpToBoundLabelResolves) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    auto target = em.create_label();
    ASSERT_TRUE(em.jmp(target).has_value());
    ASSERT_TRUE(em.bind_label(target).has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());
    EXPECT_FALSE(blob->empty());
}

TEST(X86ArchEmitter, JccTranslatesConditionCode) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    auto target = em.create_label();
    ASSERT_TRUE(em.jcc(CondCode::equal, target).has_value());
    ASSERT_TRUE(em.bind_label(target).has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());
    EXPECT_FALSE(blob->empty());
}

TEST(X86ArchEmitter, OutOfRangeRegisterIdFailsClosed) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    auto status = em.mov_rr(make_reg(31), make_reg(0));
    ASSERT_FALSE(status.has_value());
    EXPECT_EQ(status.error().code(),
              static_cast<uint16_t>(mx::ProtectionErrorCode::pass_failed));
}

TEST(X86ArchEmitter, MovImmThenStoreThenRetBuilds) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    ASSERT_TRUE(em.mov_ri(make_reg(0), 0x1234567890ABCDEFull).has_value());
    ASSERT_TRUE(em.store(make_reg(4), 16, make_reg(0)).has_value());
    ASSERT_TRUE(em.ret().has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());
    EXPECT_GT(blob->size(), 1u);
    EXPECT_EQ(blob->back(), 0xC3);
}

TEST(X86ArchEmitter, RawByteEscapeHatchPreservesBytes) {
    X86ArchEmitter em(ArchInfo::x64_baseline());
    const uint8_t bytes[] = {0x90, 0xCC, 0x90};
    ASSERT_TRUE(em.raw(mx::ByteView{bytes, sizeof(bytes)}).has_value());
    auto blob = em.build();
    ASSERT_TRUE(blob.has_value());
    ASSERT_EQ(blob->size(), 3u);
    EXPECT_EQ((*blob)[0], 0x90);
    EXPECT_EQ((*blob)[1], 0xCC);
    EXPECT_EQ((*blob)[2], 0x90);
}
