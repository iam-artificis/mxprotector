/**
 * @file trace_hints_serialize.cpp
 * @brief [BUILDER] TraceHints::to_json — рукописный JSON-writer по
 *        schema v1.
 *
 * @details Отделён от `trace_hints.cpp` исключительно ради LOC-лимита
 *          (~300 строк на файл). Все функции here — private detail
 *          того же namespace `mx::analysis`; TraceHints::to_json()
 *          вызывает их из этого TU.
 *
 * @note Schema v1 контракт: `schema_version`, `build`, `sections`,
 *       `cff`, `vm`, `guard`, `strings`, `iat`. Аддитивные поля в
 *       уже существующих объектах разрешены без бампа версии.
 */

#include "mxprotector/analysis/trace_hints.hpp"

#include <cstdio>
#include <format>

namespace mx::analysis {
namespace {

// ----------------------------------------------------------------------------
// JSON primitives
// ----------------------------------------------------------------------------

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

void append_uint_field(std::string& out,
                       std::string_view indent,
                       std::string_view key,
                       std::uint32_t value,
                       bool trailing_comma)
{
    out.append(std::format("{}\"{}\": {}{}\n",
        indent, key, value, trailing_comma ? "," : ""));
}

// ----------------------------------------------------------------------------
// Section writers
// ----------------------------------------------------------------------------

void write_build(std::string& out, const TraceHintsBuild& b) {
    out.append("  \"build\": {\n");
    append_string_field(out, "    ", "input",     b.input,     true);
    append_string_field(out, "    ", "output",    b.output,    true);
    append_string_field(out, "    ", "level",     b.level,     true);
    append_string_field(out, "    ", "timestamp", b.timestamp, false);
    out.append("  },\n");
}

void write_sections(std::string& out,
                    const std::vector<TraceHintsSection>& secs)
{
    out.append("  \"sections\": {");
    if (secs.empty()) {
        out.append("},\n");
        return;
    }
    out.push_back('\n');
    for (std::size_t i = 0; i < secs.size(); ++i) {
        const auto& s = secs[i];
        out.append("    \"");
        append_json_escaped(out, s.role);
        out.append("\": {\n");
        append_string_field(out, "      ", "name",            s.name,            true);
        append_uint_field  (out, "      ", "rva",             s.rva,             true);
        append_uint_field  (out, "      ", "size",            s.size,            true);
        append_uint_field  (out, "      ", "characteristics", s.characteristics, false);
        out.append("    }");
        if (i + 1 < secs.size()) out.push_back(',');
        out.push_back('\n');
    }
    out.append("  },\n");
}

void write_cff_state(std::string& out, const CffStateLabel& s, bool last) {
    out.append("      {\n");
    append_uint_field  (out, "        ", "id",                   s.id,                   true);
    append_uint_field  (out, "        ", "dispatcher_entry_rva", s.dispatcher_entry_rva, true);
    append_uint_field  (out, "        ", "source_bb_rva",        s.source_bb_rva,        true);
    append_string_field(out, "        ", "kind",                 cff_state_kind_name(s.kind), false);
    out.append(last ? "      }\n" : "      },\n");
}

void write_cff_predicate(std::string& out, const CffPredicateLabel& p, bool last) {
    out.append("      {\n");
    append_uint_field  (out, "        ", "id",   p.id,  true);
    append_uint_field  (out, "        ", "rva",  p.rva, true);
    append_string_field(out, "        ", "kind", predicate_kind_name(p.kind), false);
    out.append(last ? "      }\n" : "      },\n");
}

void write_cff(std::string& out, const CffHints& c) {
    out.append("  \"cff\": {\n");
    append_uint_field(out, "    ", "dispatcher_rva", c.dispatcher_rva, true);
    append_uint_field(out, "    ", "state_var_rva",  c.state_var_rva,  true);

    out.append("    \"states\": [");
    if (c.states.empty()) {
        out.append("],\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < c.states.size(); ++i) {
            write_cff_state(out, c.states[i], i + 1 == c.states.size());
        }
        out.append("    ],\n");
    }

    out.append("    \"predicates\": [");
    if (c.predicates.empty()) {
        out.append("]\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < c.predicates.size(); ++i) {
            write_cff_predicate(out, c.predicates[i], i + 1 == c.predicates.size());
        }
        out.append("    ]\n");
    }
    out.append("  },\n");
}

void write_vm_handler(std::string& out, const VmHandlerLabel& h, bool last) {
    out.append("      {\n");
    append_uint_field  (out, "        ", "id",     h.id,     true);
    append_uint_field  (out, "        ", "rva",    h.rva,    true);
    append_uint_field  (out, "        ", "size",   h.size,   true);
    append_string_field(out, "        ", "opcode", h.opcode, false);
    out.append(last ? "      }\n" : "      },\n");
}

void write_vm(std::string& out, const VmHints& v) {
    out.append("  \"vm\": {\n");
    append_uint_field(out, "    ", "dispatcher_rva",    v.dispatcher_rva,    true);
    append_uint_field(out, "    ", "handler_table_rva", v.handler_table_rva, true);

    out.append("    \"handlers\": [");
    if (v.handlers.empty()) {
        out.append("]\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < v.handlers.size(); ++i) {
            write_vm_handler(out, v.handlers[i], i + 1 == v.handlers.size());
        }
        out.append("    ]\n");
    }
    out.append("  },\n");
}

void write_guard(std::string& out, const GuardHints& g) {
    out.append("  \"guard\": {");
    if (g.regions.empty()) {
        out.append(" \"regions\": [] },\n");
        return;
    }
    out.append("\n    \"regions\": [\n");
    for (std::size_t i = 0; i < g.regions.size(); ++i) {
        const auto& r = g.regions[i];
        const bool last = (i + 1 == g.regions.size());
        out.append("      {\n");
        append_uint_field(out, "        ", "id",   r.id,   true);
        append_uint_field(out, "        ", "rva",  r.rva,  true);
        append_uint_field(out, "        ", "size", r.size, false);
        out.append(last ? "      }\n" : "      },\n");
    }
    out.append("    ]\n  },\n");
}

void write_strings(std::string& out, const StringHints& s) {
    out.append("  \"strings\": {");
    if (s.slots.empty()) {
        out.append(" \"slots\": [] },\n");
        return;
    }
    out.append("\n    \"slots\": [\n");
    for (std::size_t i = 0; i < s.slots.size(); ++i) {
        const auto& slot = s.slots[i];
        const bool last = (i + 1 == s.slots.size());
        out.append("      {\n");
        append_uint_field(out, "        ", "id",            slot.id,            true);
        append_uint_field(out, "        ", "desc_rva",      slot.desc_rva,      true);
        append_uint_field(out, "        ", "plaintext_len", slot.plaintext_len, false);
        out.append(last ? "      }\n" : "      },\n");
    }
    out.append("    ]\n  },\n");
}

void write_iat(std::string& out, const IatHints& i) {
    out.append(std::format(
        "  \"iat\": {{ \"rva\": {}, \"size\": {} }},\n",
        i.rva, i.size));
}

void write_mutation_site(std::string& out, const MutationSiteLabel& s, bool last) {
    out.append("      {\n");
    append_uint_field  (out, "        ", "rva",           s.rva,           true);
    append_uint_field  (out, "        ", "original_size", s.original_size, true);
    append_uint_field  (out, "        ", "mutated_size",  s.mutated_size,  true);
    append_string_field(out, "        ", "kind", mutation_site_kind_name(s.kind), false);
    out.append(last ? "      }\n" : "      },\n");
}

void write_mutation(std::string& out, const MutationHints& m) {
    out.append("  \"mutation\": {\n");

    out.append("    \"sites\": [");
    if (m.sites.empty()) {
        out.append("],\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < m.sites.size(); ++i) {
            write_mutation_site(out, m.sites[i], i + 1 == m.sites.size());
        }
        out.append("    ],\n");
    }

    out.append("    \"junk_regions\": [");
    if (m.junk_regions.empty()) {
        out.append("]\n");
    } else {
        out.push_back('\n');
        for (std::size_t i = 0; i < m.junk_regions.size(); ++i) {
            const auto& r = m.junk_regions[i];
            const bool last = (i + 1 == m.junk_regions.size());
            out.append("      {\n");
            append_uint_field(out, "        ", "rva",  r.rva,  true);
            append_uint_field(out, "        ", "size", r.size, false);
            out.append(last ? "      }\n" : "      },\n");
        }
        out.append("    ]\n");
    }

    out.append("  }\n");
}

} // namespace

// ============================================================================
// TraceHints::to_json — orchestration
// ============================================================================

std::string TraceHints::to_json() const {
    std::string out;
    out.reserve(2048);

    out.append("{\n");
    out.append("  \"schema_version\": 1,\n");
    write_build   (out, build_);
    write_sections(out, sections_);
    write_cff     (out, cff_);
    write_vm      (out, vm_);
    write_guard   (out, guard_);
    write_strings (out, strings_);
    write_iat     (out, iat_);
    write_mutation(out, mutation_);
    out.append("}\n");
    return out;
}

} // namespace mx::analysis
