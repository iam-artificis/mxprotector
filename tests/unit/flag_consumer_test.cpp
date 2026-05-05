/**
 * @file flag_consumer_test.cpp
 * @brief [TESTS] EFLAGS-read/write predicates + lookahead helper.
 *
 * The mutation engine relies on `analysis::safe_to_clobber_flags_after`
 * to skip flag-affecting rules at sites where the next instruction
 * reads EFLAGS. The predicate set here is conservative — false
 * positives cost a missed rewrite, false negatives miscompile the
 * binary — so the tests pin the boundaries explicitly:
 *
 *   * known consumers (`jcc`, `setcc`, `cmovcc`, `adc`, `sbb`, `rcl`,
 *     `rcr`, `lahf`, `into`, `pushf`, `loopcc`) → `consumes_eflags`.
 *   * full-set writers (`add`, `sub`, `and`, `or`, `xor`, `cmp`,
 *     `test`, `neg`, flag-loaders) → `writes_eflags`.
 *   * partial-set writers (`inc`, `dec`, `mul`, shifts, rotates,
 *     bit ops, `stc`/`clc`/etc.) → not writers (preserve at least
 *     one of CF/OF/AF/ZF/SF/PF).
 *   * neutrals (`mov`, `lea`, `nop`, `push`, `pop`) → neither.
 *   * lookahead — sees a consumer first → unsafe; sees a writer
 *     first → safe; falls off the end / hits a branch → unsafe.
 */

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "mxprotector/analysis/flag_consumer.hpp"
#include "mxprotector/analysis/instruction.hpp"
#include "mxprotector/protection/mutation/substitution_rules.hpp"

namespace {

mx::analysis::Instruction make_insn(
    std::string mnemonic,
    bool        is_conditional_branch = false,
    bool        is_branch             = false,
    bool        is_call               = false,
    bool        is_return             = false)
{
    return mx::analysis::Instruction(
        /*address=*/0x1000, /*length=*/2, /*raw_bytes=*/{0x90, 0x90},
        std::move(mnemonic), /*operands=*/"",
        /*is_branch=*/is_branch || is_conditional_branch,
        /*is_conditional_branch=*/is_conditional_branch,
        /*is_call=*/is_call,
        /*is_return=*/is_return,
        /*is_unconditional_jump=*/false,
        /*branch_targets=*/{});
}

// ---------------------------------------------------------------------------
// consumes_eflags — positive set
// ---------------------------------------------------------------------------

TEST(FlagConsumer, ConditionalBranchIsConsumer) {
    auto jz = make_insn("jz", /*conditional=*/true);
    EXPECT_TRUE(mx::analysis::consumes_eflags(jz));
}

TEST(FlagConsumer, SetccIsConsumer) {
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("setz")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("setne")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("setg")));
}

TEST(FlagConsumer, CmovccIsConsumer) {
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("cmovz")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("cmovne")));
}

TEST(FlagConsumer, CarryChainOpsAreConsumers) {
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("adc")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("sbb")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("rcl")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("rcr")));
}

TEST(FlagConsumer, FlagTransfersAreConsumers) {
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("lahf")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("into")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("pushfq")));
}

TEST(FlagConsumer, FlagAwareLoopsAreConsumers) {
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("loope")));
    EXPECT_TRUE(mx::analysis::consumes_eflags(make_insn("loopne")));
}

// ---------------------------------------------------------------------------
// consumes_eflags — neutral
// ---------------------------------------------------------------------------

TEST(FlagConsumer, MovIsNotConsumer) {
    EXPECT_FALSE(mx::analysis::consumes_eflags(make_insn("mov")));
}

TEST(FlagConsumer, UnconditionalJmpIsNotConsumer) {
    auto jmp = make_insn(
        "jmp", /*conditional=*/false, /*is_branch=*/true);
    EXPECT_FALSE(mx::analysis::consumes_eflags(jmp));
}

TEST(FlagConsumer, CallAndRetAreNotConsumers) {
    auto call = make_insn(
        "call", /*conditional=*/false, /*is_branch=*/true,
        /*is_call=*/true);
    auto ret = make_insn(
        "ret", /*conditional=*/false, /*is_branch=*/false,
        /*is_call=*/false, /*is_return=*/true);
    EXPECT_FALSE(mx::analysis::consumes_eflags(call));
    EXPECT_FALSE(mx::analysis::consumes_eflags(ret));
}

// ---------------------------------------------------------------------------
// writes_eflags — full-set killers
// ---------------------------------------------------------------------------

TEST(FlagWriter, AluOpsAreWriters) {
    for (auto m : {"add", "sub", "cmp", "and", "or", "xor", "test"}) {
        EXPECT_TRUE(mx::analysis::writes_eflags(make_insn(m)))
            << "expected " << m << " to be a flag writer";
    }
}

TEST(FlagWriter, NegIsWriter) {
    EXPECT_TRUE(mx::analysis::writes_eflags(make_insn("neg")));
}

TEST(FlagWriter, FlagLoadsAreWriters) {
    EXPECT_TRUE(mx::analysis::writes_eflags(make_insn("popfq")));
    EXPECT_TRUE(mx::analysis::writes_eflags(make_insn("sahf")));
}

// ---------------------------------------------------------------------------
// writes_eflags — partial / no writes
// ---------------------------------------------------------------------------

TEST(FlagWriter, IncDecAreNotFullKillers) {
    // INC/DEC preserve CF — a stale CF from a prior MBA can still
    // leak to a later `JC` if INC is the only thing in between.
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("inc")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("dec")));
}

TEST(FlagWriter, ShiftsAreNotFullKillers) {
    // Count-dependent flag effects + count==0 preserves all flags.
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("shl")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("shr")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("rol")));
}

TEST(FlagWriter, MulDivAreNotFullKillers) {
    // ZF/SF/AF/PF undefined after MUL/IMUL/DIV/IDIV — cannot
    // promise full overwrite for the lookahead's purposes.
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("mul")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("imul")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("div")));
}

TEST(FlagWriter, MovAndLeaPreserveFlags) {
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("mov")));
    EXPECT_FALSE(mx::analysis::writes_eflags(make_insn("lea")));
}

// ---------------------------------------------------------------------------
// safe_to_clobber_flags_after — the lookahead walker
// ---------------------------------------------------------------------------

TEST(FlagLookahead, WriterBeforeConsumerIsSafe) {
    // ADD candidate at index 0; AND (writer) at 1; JZ at 2.
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    stream.push_back(make_insn("and"));
    stream.push_back(make_insn("jz", /*conditional=*/true));
    EXPECT_TRUE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
}

TEST(FlagLookahead, ConsumerBeforeWriterIsUnsafe) {
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    stream.push_back(make_insn("jz", /*conditional=*/true));
    stream.push_back(make_insn("and"));
    EXPECT_FALSE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
}

TEST(FlagLookahead, BranchTerminatesAsUnsafe) {
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    stream.push_back(
        make_insn("jmp", /*conditional=*/false, /*is_branch=*/true));
    EXPECT_FALSE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
}

TEST(FlagLookahead, RunOffEndIsUnsafe) {
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    stream.push_back(make_insn("mov"));
    stream.push_back(make_insn("mov"));
    EXPECT_FALSE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
}

TEST(FlagLookahead, MovsThenWriterIsSafe) {
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    stream.push_back(make_insn("mov"));
    stream.push_back(make_insn("mov"));
    stream.push_back(make_insn("xor"));
    EXPECT_TRUE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
}

TEST(FlagLookahead, LimitCutsOff) {
    std::vector<mx::analysis::Instruction> stream;
    stream.push_back(make_insn("add"));
    for (int i = 0; i < 30; ++i) {
        stream.push_back(make_insn("mov"));
    }
    stream.push_back(make_insn("xor"));
    // With the default lookahead of 8 the writer is past the limit,
    // so the walker bails out conservatively.
    EXPECT_FALSE(mx::analysis::safe_to_clobber_flags_after(stream, 0));
    // Bumping the limit reaches the writer.
    EXPECT_TRUE(mx::analysis::safe_to_clobber_flags_after(stream, 0, 64));
}

// ---------------------------------------------------------------------------
// ISubstitutionRule::affects_observable_flags — default + override
// ---------------------------------------------------------------------------

namespace {

struct DefaultRule final : public mx::ISubstitutionRule {
    [[nodiscard]] std::string_view name() const noexcept override {
        return "default-rule";
    }
    [[nodiscard]] bool matches(
        const mx::analysis::Instruction&) const override { return true; }
    [[nodiscard]] mx::ByteBuffer apply(
        const mx::analysis::Instruction&, mx::Randomizer&) const override
    {
        return {};
    }
};

struct FlagAffectingRule final : public mx::ISubstitutionRule {
    [[nodiscard]] std::string_view name() const noexcept override {
        return "flag-affecting-rule";
    }
    [[nodiscard]] bool matches(
        const mx::analysis::Instruction&) const override { return true; }
    [[nodiscard]] mx::ByteBuffer apply(
        const mx::analysis::Instruction&, mx::Randomizer&) const override
    {
        return {};
    }
    [[nodiscard]] bool affects_observable_flags() const noexcept override {
        return true;
    }
};

} // namespace

TEST(SubstitutionRule, AffectsFlagsDefaultsToFalse) {
    DefaultRule rule;
    EXPECT_FALSE(rule.affects_observable_flags());
}

TEST(SubstitutionRule, AffectsFlagsOverridable) {
    FlagAffectingRule rule;
    EXPECT_TRUE(rule.affects_observable_flags());
}

} // namespace
