/**
 * @file trace_hints.cpp
 * @brief [BUILDER] Реализация `TraceHints` — рукописный JSON-writer.
 *
 * @details Schema v1 фиксирована: `schema_version`, `build`,
 *          `sections`, `cff`, `vm`, `guard`, `strings`, `iat`.
 *          Phase 1 заполняет `build` и `sections`; остальные слоты
 *          эмитятся пустыми стабами. Последующие фазы расширяют
 *          TraceHints новыми полями и заменяют соответствующие
 *          стабы без ломки схемы.
 *
 * @note JSON-строки экранируются вручную (см. `append_json_escaped`).
 *       Pretty-print 2 пробела — sidecar читают и люди, и pydantic.
 */

#include "mxprotector/analysis/trace_hints.hpp"

#include <cstdio>
#include <format>

namespace mx::analysis {

namespace {

/// Экранирует `s` как JSON-строку и дописывает в `out`.
void append_json_escaped(std::string& out, std::string_view s) {
    for (const unsigned char c : s) {
        switch (c) {
            case '"':  out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\b': out.append("\\b");  break;
            case '\f': out.append("\\f");  break;
            case '\n': out.append("\\n");  break;
            case '\r': out.append("\\r");  break;
            case '\t': out.append("\\t");  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04X",
                                  static_cast<unsigned>(c));
                    out.append(buf);
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
}

/// Дописывает `"key": "value",` с экранированием value.
void append_string_field(std::string& out,
                         std::string_view indent,
                         std::string_view key,
                         std::string_view value,
                         bool trailing_comma)
{
    out.append(indent);
    out.push_back('"');
    out.append(key);
    out.append("\": \"");
    append_json_escaped(out, value);
    out.push_back('"');
    if (trailing_comma) out.push_back(',');
    out.push_back('\n');
}

/// Дописывает `"key": <number>[,]`.
void append_uint_field(std::string& out,
                       std::string_view indent,
                       std::string_view key,
                       std::uint32_t value,
                       bool trailing_comma)
{
    out.append(std::format("{}\"{}\": {}{}\n",
        indent, key, value, trailing_comma ? "," : ""));
}

} // namespace

// ============================================================================
// TraceHints — mutation
// ============================================================================

void TraceHints::set_build_info(std::string_view input,
                                std::string_view output,
                                std::string_view level,
                                std::string_view timestamp)
{
    build_.input     = input;
    build_.output    = output;
    build_.level     = level;
    build_.timestamp = timestamp;
}

void TraceHints::add_section(std::string_view role,
                             std::string_view name,
                             std::uint32_t rva,
                             std::uint32_t size,
                             std::uint32_t characteristics)
{
    sections_.push_back(TraceHintsSection{
        .role            = std::string(role),
        .name            = std::string(name),
        .rva             = rva,
        .size            = size,
        .characteristics = characteristics,
    });
}

// ============================================================================
// TraceHints — query
// ============================================================================

bool TraceHints::empty() const noexcept {
    return build_.input.empty()
        && build_.output.empty()
        && build_.level.empty()
        && build_.timestamp.empty()
        && sections_.empty();
}

// ============================================================================
// TraceHints — serialization
// ============================================================================

std::string TraceHints::to_json() const {
    std::string out;
    out.reserve(1024);

    out.append("{\n");
    out.append("  \"schema_version\": 1,\n");

    // build
    out.append("  \"build\": {\n");
    append_string_field(out, "    ", "input",     build_.input,     true);
    append_string_field(out, "    ", "output",    build_.output,    true);
    append_string_field(out, "    ", "level",     build_.level,     true);
    append_string_field(out, "    ", "timestamp", build_.timestamp, false);
    out.append("  },\n");

    // sections — object keyed by role
    out.append("  \"sections\": {");
    if (sections_.empty()) {
        out.append("},\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < sections_.size(); ++i) {
            const auto& s = sections_[i];
            out.append("    \"");
            append_json_escaped(out, s.role);
            out.append("\": {\n");
            append_string_field(out, "      ", "name",            s.name,            true);
            append_uint_field  (out, "      ", "rva",             s.rva,             true);
            append_uint_field  (out, "      ", "size",            s.size,            true);
            append_uint_field  (out, "      ", "characteristics", s.characteristics, false);
            out.append("    }");
            if (i + 1 < sections_.size()) out.push_back(',');
            out.push_back('\n');
        }
        out.append("  },\n");
    }

    // Stable empty stubs — populated from Phase 4 onward. Schema v1
    // freezes their shape so pydantic on the MCP side accepts the
    // document even when no labels are present.
    out.append("  \"cff\": { \"dispatcher_rva\": 0, \"state_var_rva\": 0, "
                  "\"states\": [], \"predicates\": [] },\n");
    out.append("  \"vm\": { \"dispatcher_rva\": 0, \"handler_table_rva\": 0, "
                  "\"handlers\": [] },\n");
    out.append("  \"guard\": { \"regions\": [] },\n");
    out.append("  \"strings\": { \"slots\": [] },\n");
    out.append("  \"iat\": { \"rva\": 0, \"size\": 0 }\n");

    out.append("}\n");
    return out;
}

} // namespace mx::analysis
