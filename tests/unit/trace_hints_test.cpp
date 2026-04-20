/**
 * @file trace_hints_test.cpp
 * @brief [TESTS] Юнит-тесты TraceHints — контейнер sidecar-меток.
 *
 * @details Покрывают:
 *          - Свежий контейнер пуст (leak-guard for `--trace-hints` off).
 *          - Сериализация `schema_version: 1` и стабильных стабов
 *            `cff`/`vm`/`guard`/`strings`/`iat` — контракт с
 *            pydantic-схемой на стороне MCP (sidecar.py).
 *          - Заполнение `build` блока.
 *          - Несколько секций подряд.
 *          - Экранирование спец-символов JSON (бэкслеш, кавычки,
 *            управляющие символы).
 *
 * @note Тесты сверяют подстроки, а не точное байт-сравнение — layout
 *       JSON не часть фиксированного контракта (pydantic парсит
 *       структуру, не текст).
 */

#include "mxprotector/analysis/trace_hints.hpp"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace mx::analysis {

namespace {

/// Удобный helper: истина если `haystack` содержит `needle`.
[[nodiscard]] bool contains(std::string_view haystack,
                            std::string_view needle)
{
    return haystack.find(needle) != std::string_view::npos;
}

} // namespace

// ============================================================================
// Leak guard — свежий контейнер ничего не аккумулирует.
// ============================================================================

TEST(TraceHintsTest, FreshContainerIsEmpty) {
    TraceHints h;
    EXPECT_TRUE(h.empty());
}

TEST(TraceHintsTest, AddingSectionClearsEmpty) {
    TraceHints h;
    h.add_section("vm", ".ab1c", 0x1000, 0x400, 0x60000020);
    EXPECT_FALSE(h.empty());
}

TEST(TraceHintsTest, SettingBuildInfoClearsEmpty) {
    TraceHints h;
    h.set_build_info("in.exe", "out.exe", "strong", "2026-04-20T12:00:00Z");
    EXPECT_FALSE(h.empty());
}

// ============================================================================
// Schema v1 contract — всегда эмитятся schema_version и пустые стабы.
// ============================================================================

TEST(TraceHintsTest, EmptyContainerSerializesSchemaV1) {
    TraceHints h;
    const auto json = h.to_json();

    EXPECT_TRUE(contains(json, "\"schema_version\": 1"));
    EXPECT_TRUE(contains(json, "\"build\""));
    EXPECT_TRUE(contains(json, "\"sections\": {}"));
    EXPECT_TRUE(contains(json, "\"cff\""));
    EXPECT_TRUE(contains(json, "\"vm\""));
    EXPECT_TRUE(contains(json, "\"guard\""));
    EXPECT_TRUE(contains(json, "\"strings\""));
    EXPECT_TRUE(contains(json, "\"iat\""));

    EXPECT_TRUE(contains(json, "\"states\": []"));
    EXPECT_TRUE(contains(json, "\"predicates\": []"));
    EXPECT_TRUE(contains(json, "\"handlers\": []"));
    EXPECT_TRUE(contains(json, "\"regions\": []"));
    EXPECT_TRUE(contains(json, "\"slots\": []"));
}

TEST(TraceHintsTest, BuildInfoAppearsInJson) {
    TraceHints h;
    h.set_build_info("samples/hello.exe",
                     "samples/hello.mx.exe",
                     "strong",
                     "2026-04-20T12:34:56Z");
    const auto json = h.to_json();

    EXPECT_TRUE(contains(json, "\"input\": \"samples/hello.exe\""));
    EXPECT_TRUE(contains(json, "\"output\": \"samples/hello.mx.exe\""));
    EXPECT_TRUE(contains(json, "\"level\": \"strong\""));
    EXPECT_TRUE(contains(json, "\"timestamp\": \"2026-04-20T12:34:56Z\""));
}

// ============================================================================
// Sections — массив, правильные значения, несколько записей.
// ============================================================================

TEST(TraceHintsTest, SectionsSerializedWithRoleAndFields) {
    TraceHints h;
    h.add_section("vm",     ".ab1c", 0x1000, 0x400, 0x60000020);
    h.add_section("packer", ".def2", 0x2000, 0x800, 0xE0000020);
    const auto json = h.to_json();

    // Roles as object keys
    EXPECT_TRUE(contains(json, "\"vm\": {"));
    EXPECT_TRUE(contains(json, "\"packer\": {"));

    // Runtime names (randomized per-build)
    EXPECT_TRUE(contains(json, "\"name\": \".ab1c\""));
    EXPECT_TRUE(contains(json, "\"name\": \".def2\""));

    // Numeric fields — decimal form
    EXPECT_TRUE(contains(json, "\"rva\": 4096"));    // 0x1000
    EXPECT_TRUE(contains(json, "\"rva\": 8192"));    // 0x2000
    EXPECT_TRUE(contains(json, "\"size\": 1024"));   // 0x400
    EXPECT_TRUE(contains(json, "\"size\": 2048"));   // 0x800
    EXPECT_TRUE(contains(json, "\"characteristics\": 1610612768"));  // 0x60000020
    EXPECT_TRUE(contains(json, "\"characteristics\": 3758096416")); // 0xE0000020
}

// ============================================================================
// JSON escaping — бэкслеш, двойная кавычка, \n, управляющие.
// ============================================================================

TEST(TraceHintsTest, BackslashesEscaped) {
    TraceHints h;
    h.set_build_info(R"(C:\Users\me\hello.exe)",
                     R"(C:\Users\me\hello.mx.exe)",
                     "strong",
                     "2026-04-20T12:00:00Z");
    const auto json = h.to_json();

    // Windows path: each '\' must become '\\' in the JSON text.
    EXPECT_TRUE(contains(json, R"("input": "C:\\Users\\me\\hello.exe")"));
    EXPECT_TRUE(contains(json, R"("output": "C:\\Users\\me\\hello.mx.exe")"));
}

TEST(TraceHintsTest, QuotesAndControlCharsEscaped) {
    TraceHints h;
    h.add_section("role_with_\"quote\"",
                  "name\nwith_newline",
                  0, 0, 0);
    const auto json = h.to_json();

    EXPECT_TRUE(contains(json, "role_with_\\\"quote\\\""));
    EXPECT_TRUE(contains(json, "name\\nwith_newline"));
}

TEST(TraceHintsTest, LowAsciiEscapedAsUnicode) {
    TraceHints h;
    h.add_section(std::string("role\x01"),
                  std::string("name\x1F"),
                  0, 0, 0);
    const auto json = h.to_json();

    EXPECT_TRUE(contains(json, "role\\u0001"));
    EXPECT_TRUE(contains(json, "name\\u001F"));
}

// ============================================================================
// Trailing newline — удобство tail'а.
// ============================================================================

TEST(TraceHintsTest, JsonEndsWithNewline) {
    TraceHints h;
    const auto json = h.to_json();
    ASSERT_FALSE(json.empty());
    EXPECT_EQ(json.back(), '\n');
}

// ============================================================================
// Phase 4A — CFF / VM / Guard / Strings / IAT
// ============================================================================

TEST(TraceHintsTest, CffDispatcherAndStatesSerialized) {
    TraceHints h;
    h.set_cff_dispatcher(0x4000, 0x5010);
    h.add_cff_state(0, 0x4100, 0x1234, CffStateKind::original);
    h.add_cff_state(1, 0x4140, 0x5678, CffStateKind::predicate);
    h.add_cff_state(2, 0x4180, 0,      CffStateKind::bogus);
    h.add_opaque_predicate(0, 0x4200, PredicateKind::opaque_hash);
    h.add_opaque_predicate(1, 0x4220, PredicateKind::mba_transition);

    EXPECT_FALSE(h.empty());
    const auto json = h.to_json();

    // Dispatcher + state_var RVAs
    EXPECT_TRUE(contains(json, "\"dispatcher_rva\": 16384"));  // 0x4000
    EXPECT_TRUE(contains(json, "\"state_var_rva\": 20496"));   // 0x5010

    // States — ids + rvas + kinds
    EXPECT_TRUE(contains(json, "\"dispatcher_entry_rva\": 16640"));  // 0x4100
    EXPECT_TRUE(contains(json, "\"source_bb_rva\": 4660"));          // 0x1234
    EXPECT_TRUE(contains(json, "\"kind\": \"original\""));
    EXPECT_TRUE(contains(json, "\"kind\": \"predicate\""));
    EXPECT_TRUE(contains(json, "\"kind\": \"bogus\""));

    // Predicates — two with different kinds
    EXPECT_TRUE(contains(json, "\"kind\": \"opaque_hash\""));
    EXPECT_TRUE(contains(json, "\"kind\": \"mba_transition\""));

    // Read-back API
    EXPECT_EQ(h.cff().dispatcher_rva, 0x4000u);
    EXPECT_EQ(h.cff().state_var_rva,  0x5010u);
    ASSERT_EQ(h.cff().states.size(),     size_t{3});
    ASSERT_EQ(h.cff().predicates.size(), size_t{2});
    EXPECT_EQ(h.cff().states[2].kind, CffStateKind::bogus);
}

TEST(TraceHintsTest, VmDispatcherAndHandlersSerialized) {
    TraceHints h;
    h.set_vm_dispatcher(0x10000, 0x10800);
    h.add_vm_handler(0, 0x10900, 64, "ADD_R64");
    h.add_vm_handler(1, 0x10940, 48, "XOR_R64");

    const auto json = h.to_json();
    EXPECT_TRUE(contains(json, "\"dispatcher_rva\": 65536"));
    EXPECT_TRUE(contains(json, "\"handler_table_rva\": 67584"));
    EXPECT_TRUE(contains(json, "\"opcode\": \"ADD_R64\""));
    EXPECT_TRUE(contains(json, "\"opcode\": \"XOR_R64\""));
    EXPECT_TRUE(contains(json, "\"rva\": 67840"));   // 0x10900
    EXPECT_TRUE(contains(json, "\"size\": 64"));

    EXPECT_EQ(h.vm().handlers.size(), size_t{2});
    EXPECT_EQ(h.vm().handlers.front().opcode, "ADD_R64");
}

TEST(TraceHintsTest, GuardRegionsSerialized) {
    TraceHints h;
    h.add_guard_region(0, 0x20000, 128);
    h.add_guard_region(1, 0x20080, 256);

    const auto json = h.to_json();
    // Each region emits id, rva, size
    EXPECT_TRUE(contains(json, "\"id\": 0"));
    EXPECT_TRUE(contains(json, "\"id\": 1"));
    EXPECT_TRUE(contains(json, "\"rva\": 131072"));  // 0x20000
    EXPECT_TRUE(contains(json, "\"size\": 128"));
    EXPECT_TRUE(contains(json, "\"size\": 256"));

    EXPECT_EQ(h.guard().regions.size(), size_t{2});
}

TEST(TraceHintsTest, StringSlotsSerialized) {
    TraceHints h;
    h.add_string_slot(0, 0x30000, 16);
    h.add_string_slot(1, 0x30020, 48);

    const auto json = h.to_json();
    EXPECT_TRUE(contains(json, "\"desc_rva\": 196608"));   // 0x30000
    EXPECT_TRUE(contains(json, "\"plaintext_len\": 16"));
    EXPECT_TRUE(contains(json, "\"plaintext_len\": 48"));

    EXPECT_EQ(h.strings().slots.size(), size_t{2});
}

TEST(TraceHintsTest, IatSerialized) {
    TraceHints h;
    h.set_iat(0x2000, 0x400);

    const auto json = h.to_json();
    EXPECT_TRUE(contains(json, "\"iat\": { \"rva\": 8192, \"size\": 1024 }"));
    EXPECT_EQ(h.iat().rva,  0x2000u);
    EXPECT_EQ(h.iat().size, 0x400u);
}

TEST(TraceHintsTest, EmptyFlagsAllPhase4AFields) {
    // Each Phase 4A mutation alone should break emptiness.
    {
        TraceHints h; h.set_cff_dispatcher(0x1000, 0);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_cff_state(0, 0, 0, CffStateKind::original);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_opaque_predicate(0, 0, PredicateKind::opaque_hash);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.set_vm_dispatcher(0x1000, 0);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_vm_handler(0, 0, 0, "NOP");
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_guard_region(0, 0, 0);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_string_slot(0, 0, 0);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.set_iat(0x1000, 0);
        EXPECT_FALSE(h.empty());
    }
}

TEST(TraceHintsTest, AllSectionsCoexistInOneJson) {
    TraceHints h;
    h.set_build_info("in.exe", "out.exe", "strong", "t");
    h.add_section("packer", ".abc", 0x5000, 0x200, 0x60000020);
    h.set_cff_dispatcher(0x4000, 0x5010);
    h.add_cff_state(0, 0x4100, 0x1234, CffStateKind::original);
    h.add_opaque_predicate(0, 0x4200, PredicateKind::opaque_hash);
    h.set_vm_dispatcher(0x10000, 0x10800);
    h.add_vm_handler(0, 0x10900, 64, "ADD_R64");
    h.add_guard_region(0, 0x20000, 128);
    h.add_string_slot(0, 0x30000, 16);
    h.set_iat(0x2000, 0x400);
    h.add_mutation_site(0x1000, 3, 3, MutationSiteKind::substitution);
    h.add_junk_region(0x1100, 12);

    const auto json = h.to_json();

    // Ensure the final document is still valid: schema_version first,
    // every top-level key present, ends with '\n' + '}\n'.
    EXPECT_TRUE(contains(json, "\"schema_version\": 1"));
    for (std::string_view top : {"\"build\"", "\"sections\"", "\"cff\"",
                                 "\"vm\"", "\"guard\"", "\"strings\"",
                                 "\"iat\"", "\"mutation\""})
    {
        EXPECT_TRUE(contains(json, top)) << "missing top-level key: " << top;
    }
    EXPECT_EQ(json.back(), '\n');
    // Closing brace sits on its own line just before trailing newline.
    ASSERT_GT(json.size(), size_t{2});
    EXPECT_EQ(json[json.size() - 2], '}');
}

// ============================================================================
// Phase 4D — Mutation (sites + junk regions)
// ============================================================================

TEST(TraceHintsTest, MutationSitesAndJunkSerialized) {
    TraceHints h;
    h.add_mutation_site(0x2000, 5, 5, MutationSiteKind::substitution);
    h.add_mutation_site(0x2010, 4, 7, MutationSiteKind::split);
    h.add_mutation_site(0x2020, 3, 3, MutationSiteKind::reassign);
    h.add_junk_region(0x3000, 16);
    h.add_junk_region(0x3100, 8);

    const auto json = h.to_json();
    // All three kinds round-trip through the serializer.
    EXPECT_TRUE(contains(json, "\"kind\": \"substitution\""));
    EXPECT_TRUE(contains(json, "\"kind\": \"split\""));
    EXPECT_TRUE(contains(json, "\"kind\": \"reassign\""));
    // Site numerics
    EXPECT_TRUE(contains(json, "\"rva\": 8192"));   // 0x2000
    EXPECT_TRUE(contains(json, "\"original_size\": 4"));
    EXPECT_TRUE(contains(json, "\"mutated_size\": 7"));
    // Junk regions
    EXPECT_TRUE(contains(json, "\"rva\": 12288"));  // 0x3000
    EXPECT_TRUE(contains(json, "\"size\": 16"));

    // Read-back API
    ASSERT_EQ(h.mutation().sites.size(),         size_t{3});
    ASSERT_EQ(h.mutation().junk_regions.size(), size_t{2});
    EXPECT_EQ(h.mutation().sites[1].kind, MutationSiteKind::split);
}

TEST(TraceHintsTest, MutationBreaksEmpty) {
    {
        TraceHints h; h.add_mutation_site(0, 0, 0, MutationSiteKind::substitution);
        EXPECT_FALSE(h.empty());
    }
    {
        TraceHints h; h.add_junk_region(0, 0);
        EXPECT_FALSE(h.empty());
    }
}

} // namespace mx::analysis
