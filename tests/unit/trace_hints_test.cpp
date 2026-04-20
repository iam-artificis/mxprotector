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

} // namespace mx::analysis
