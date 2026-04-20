/**
 * @file section_name_pool_test.cpp
 * @brief [TESTS] Stealth section-name pools.
 *
 * The pools are tiny compile-time-constant vectors plus a thin
 * Fisher–Yates sampler. The tests here pin three things:
 *
 *   1. Invariants on the pool contents themselves — ≤ 8 ASCII
 *      bytes per name (PE section-name limit), valid leading
 *      char (`.` for user-mode, uppercase letter for driver),
 *      ≥ 5 entries per pool, no duplicates inside one pool.
 *   2. `pick_section_names` correctness — five distinct names,
 *      drawn from the right pool per `BinaryKind`, and the
 *      `--debug-sections` short-circuit returning the canonical
 *      `.mx*` set regardless of kind.
 *   3. Determinism per seed — two runs with the same `Randomizer`
 *      seed produce byte-identical `SectionNameMap`s.
 */

#include <gtest/gtest.h>

#include <set>
#include <string>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/target/target_info.hpp"
#include "cli/section_name_pool.hpp"

namespace {

using mx::Randomizer;
using mx::pick_section_names;
using mx::SectionNameMap;
using mx::stealth_section_pool_for;
using mx::target::BinaryKind;

// --------------------------------------------------------------------
// Pool invariants
// --------------------------------------------------------------------

void check_pool_invariants(
    const std::vector<std::string>& pool,
    bool expect_leading_dot)
{
    ASSERT_GE(pool.size(), 5u) << "pool must have ≥ 5 entries so "
                                  "pick_section_names can draw "
                                  "5 distinct names";

    std::set<std::string> uniq(pool.begin(), pool.end());
    EXPECT_EQ(uniq.size(), pool.size())
        << "pool contains duplicate entries";

    for (const auto& name : pool) {
        EXPECT_LE(name.size(), 8u)
            << "`" << name << "` exceeds 8-byte PE section name limit";
        EXPECT_FALSE(name.empty()) << "pool entry is empty";
        if (expect_leading_dot) {
            EXPECT_EQ(name[0], '.')
                << "`" << name << "` should start with '.' (user-mode idiom)";
        } else {
            // Kernel drivers conventionally use uppercase section
            // names with no leading dot (ntoskrnl style).
            EXPECT_GE(name[0], 'A') << "`" << name
                << "` should start with an uppercase letter (driver idiom)";
            EXPECT_LE(name[0], 'Z') << "`" << name
                << "` should start with an uppercase letter (driver idiom)";
        }
    }
}

TEST(SectionNamePool, UserModePoolInvariants) {
    const auto& exe_pool = stealth_section_pool_for(BinaryKind::executable);
    const auto& dll_pool = stealth_section_pool_for(BinaryKind::dynamic_library);
    EXPECT_EQ(&exe_pool, &dll_pool)
        << "EXE and DLL should share the user-mode pool";
    check_pool_invariants(exe_pool, /*expect_leading_dot=*/true);
}

TEST(SectionNamePool, DriverPoolInvariants) {
    const auto& drv = stealth_section_pool_for(BinaryKind::kernel_driver);
    check_pool_invariants(drv, /*expect_leading_dot=*/false);
}

TEST(SectionNamePool, UserModeAndDriverPoolsAreDistinct) {
    // The two pools should have no entry in common — otherwise a
    // shared entry defeats the per-kind camouflage (a user-mode
    // `.tls1` would appear just as often as a driver `PAGEBGFX`).
    const auto& user_pool = stealth_section_pool_for(BinaryKind::executable);
    const auto& drv_pool  = stealth_section_pool_for(BinaryKind::kernel_driver);
    std::set<std::string> user_set(user_pool.begin(), user_pool.end());
    for (const auto& d : drv_pool) {
        EXPECT_EQ(user_set.count(d), 0u)
            << "driver name `" << d
            << "` unexpectedly also present in the user-mode pool";
    }
}

TEST(SectionNamePool, DriverPoolExcludesCollidingBaseNames) {
    // Real drivers routinely ship with `INIT`, `PAGE`, and
    // `NONPAGE` sections. If the pool offered those names, an
    // injected section would collide with the input's existing
    // one — SectionManager would probably recover, but the
    // ambiguity is hostile to analysis and disassembly. Pin the
    // exclusion.
    const auto& drv = stealth_section_pool_for(BinaryKind::kernel_driver);
    for (const auto& name : drv) {
        EXPECT_NE(name, "INIT")
            << "base driver name `INIT` should be absent from the pool "
               "(collides with nearly every real driver)";
        EXPECT_NE(name, "PAGE")
            << "base driver name `PAGE` should be absent from the pool";
        EXPECT_NE(name, "NONPAGE")
            << "base driver name `NONPAGE` should be absent from the pool";
    }
}

TEST(SectionNamePool, UnknownKindFallsBackToUserMode) {
    const auto& fallback = stealth_section_pool_for(BinaryKind::unknown);
    const auto& user = stealth_section_pool_for(BinaryKind::executable);
    EXPECT_EQ(&fallback, &user);
}

// --------------------------------------------------------------------
// pick_section_names behaviour
// --------------------------------------------------------------------

void check_all_distinct(const SectionNameMap& names) {
    std::set<std::string> s{
        names.vm, names.cff, names.packer, names.str, names.guard};
    EXPECT_EQ(s.size(), 5u) << "the 5 picked names must all differ";
}

TEST(SectionNamePool, DebugFlagReturnsFixedSetForExecutable) {
    Randomizer rng{0xBEEFull};
    auto names = pick_section_names(
        BinaryKind::executable,
        /*debug_section_names=*/true, rng);
    EXPECT_EQ(names.vm,     ".mxvm");
    EXPECT_EQ(names.cff,    ".mxprot1");
    EXPECT_EQ(names.packer, ".mxpack");
    EXPECT_EQ(names.str,    ".mxstr");
    EXPECT_EQ(names.guard,  ".mxguard");
}

TEST(SectionNamePool, DebugFlagIgnoresKind) {
    // `--debug-sections` on a driver build should still yield the
    // `.mx*` set — the developer expects identical names across
    // debug runs regardless of the input binary shape.
    Randomizer rng{0xBEEFull};
    auto names = pick_section_names(
        BinaryKind::kernel_driver,
        /*debug_section_names=*/true, rng);
    EXPECT_EQ(names.vm,     ".mxvm");
    EXPECT_EQ(names.cff,    ".mxprot1");
    EXPECT_EQ(names.packer, ".mxpack");
    EXPECT_EQ(names.str,    ".mxstr");
    EXPECT_EQ(names.guard,  ".mxguard");
}

TEST(SectionNamePool, ExecutableDrawsFromUserModePool) {
    Randomizer rng{0x1234ull};
    auto names = pick_section_names(
        BinaryKind::executable,
        /*debug_section_names=*/false, rng);
    check_all_distinct(names);

    const auto& pool = stealth_section_pool_for(BinaryKind::executable);
    std::set<std::string> pool_set(pool.begin(), pool.end());
    EXPECT_NE(pool_set.count(names.vm),     0u) << names.vm;
    EXPECT_NE(pool_set.count(names.cff),    0u) << names.cff;
    EXPECT_NE(pool_set.count(names.packer), 0u) << names.packer;
    EXPECT_NE(pool_set.count(names.str),    0u) << names.str;
    EXPECT_NE(pool_set.count(names.guard),  0u) << names.guard;
}

TEST(SectionNamePool, DriverDrawsFromDriverPool) {
    Randomizer rng{0x1234ull};
    auto names = pick_section_names(
        BinaryKind::kernel_driver,
        /*debug_section_names=*/false, rng);
    check_all_distinct(names);

    const auto& pool = stealth_section_pool_for(BinaryKind::kernel_driver);
    std::set<std::string> pool_set(pool.begin(), pool.end());
    EXPECT_NE(pool_set.count(names.vm),     0u) << names.vm;
    EXPECT_NE(pool_set.count(names.cff),    0u) << names.cff;
    EXPECT_NE(pool_set.count(names.packer), 0u) << names.packer;
    EXPECT_NE(pool_set.count(names.str),    0u) << names.str;
    EXPECT_NE(pool_set.count(names.guard),  0u) << names.guard;

    // Cross-check: none of the picked names look like user-mode.
    const auto& user_pool = stealth_section_pool_for(BinaryKind::executable);
    std::set<std::string> user_set(user_pool.begin(), user_pool.end());
    EXPECT_EQ(user_set.count(names.vm),     0u);
    EXPECT_EQ(user_set.count(names.cff),    0u);
    EXPECT_EQ(user_set.count(names.packer), 0u);
    EXPECT_EQ(user_set.count(names.str),    0u);
    EXPECT_EQ(user_set.count(names.guard),  0u);
}

TEST(SectionNamePool, DeterministicForSameSeed) {
    // Two fresh Randomizers with the same seed must produce the
    // same SectionNameMap — this underpins reproducible builds
    // when the user sets the RNG seed explicitly for CI.
    Randomizer rng_a{0xCAFEull};
    Randomizer rng_b{0xCAFEull};
    auto a = pick_section_names(BinaryKind::executable, false, rng_a);
    auto b = pick_section_names(BinaryKind::executable, false, rng_b);
    EXPECT_EQ(a.vm,     b.vm);
    EXPECT_EQ(a.cff,    b.cff);
    EXPECT_EQ(a.packer, b.packer);
    EXPECT_EQ(a.str,    b.str);
    EXPECT_EQ(a.guard,  b.guard);
}

TEST(SectionNamePool, DifferentSeedsUsuallyDifferentNames) {
    // Probabilistic sanity: distinct seeds should shuffle the
    // pool into distinct permutations often enough that at least
    // one of the 5 slots differs. With a pool of ≥ 16 entries the
    // probability of full-match collision is < 1 in 16! — vanishing.
    Randomizer rng_a{0x1111ull};
    Randomizer rng_b{0x2222ull};
    auto a = pick_section_names(BinaryKind::kernel_driver, false, rng_a);
    auto b = pick_section_names(BinaryKind::kernel_driver, false, rng_b);
    const bool any_diff =
        a.vm != b.vm || a.cff != b.cff || a.packer != b.packer
        || a.str != b.str || a.guard != b.guard;
    EXPECT_TRUE(any_diff) << "two distinct seeds produced byte-identical "
                             "section maps — bump the seeds or check the "
                             "Fisher-Yates shuffle";
}

} // namespace
