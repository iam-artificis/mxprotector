/**
 * @file map_parser.cpp
 * @brief [BUILDER] Реализация парсера .map файлов формата MSVC.
 *
 * @details Разбирает секции .map файла:
 *          1. "Preferred load address" → image_base
 *          2. "Start Length Name Class" → информация о секциях
 *          3. "Address Publics by Value Rva+Base Lib:Object" → символы
 *
 *          Вычисляет размер каждой функции как разницу RVA до следующей функции
 *          в той же секции. Фильтрует CRT-функции по колонке Lib:Object.
 */

#include "mxprotector/protection/cfg/map_parser.hpp"

#include <algorithm>
#include <fstream>
#include <format>
#include <sstream>
#include <string>

namespace mx {

namespace {

struct MapSection {
    uint32_t index  = 0;
    uint32_t offset = 0;
    uint32_t length = 0;
    std::string name;
    std::string cls;
};

std::string trim(const std::string& s) {
    const auto begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

bool parse_address(const std::string& addr_str, uint32_t& section_idx, uint32_t& offset) {
    const auto colon_pos = addr_str.find(':');
    if (colon_pos == std::string::npos || colon_pos == 0) return false;

    try {
        section_idx = static_cast<uint32_t>(std::stoul(addr_str.substr(0, colon_pos), nullptr, 16));
        offset = static_cast<uint32_t>(std::stoul(addr_str.substr(colon_pos + 1), nullptr, 16));
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_rva_base(const std::string& rva_str, Va& rva_base) {
    try {
        rva_base = std::stoull(rva_str, nullptr, 16);
        return true;
    } catch (...) {
        return false;
    }
}

} // anonymous namespace

bool MapParser::is_library_object(const std::string& obj_name) {
    if (obj_name.empty()) return true;

    static const std::string_view lib_prefixes[] = {
        "LIBCMT:",    "libcmt:",
        "LIBCMTD:",   "libcmtd:",
        "MSVCRT:",    "msvcrt:",
        "MSVCRTD:",   "msvcrtd:",
        "libucrt:",   "LIBUCRT:",
        "libvcruntime:", "LIBVCRUNTIME:",
        "vccorlib:",  "vcruntime:",
        "KERNEL32:",  "kernel32:",
        "ntdll:",     "ucrt:",
        "oldnames:",  "legacy_stdio",
    };

    for (const auto& prefix : lib_prefixes) {
        if (obj_name.find(prefix) != std::string::npos) {
            return true;
        }
    }

    if (obj_name.find(".lib:") != std::string::npos) {
        return true;
    }

    if (obj_name.find("api-ms-win") != std::string::npos) {
        return true;
    }

    return false;
}

bool MapParser::is_crt_function_name(const std::string& name) {
    if (name.empty()) return false;

    // Double-underscore: always compiler/CRT internal
    if (name.starts_with("__")) return true;

    // Single underscore + uppercase or underscore: CRT convention in x64
    if (name[0] == '_' && name.size() > 1 && (name[1] == '_' || std::isupper(name[1]))) {
        return true;
    }

    // MSVC mangled CRT names: ?__scrt*, ??_G (scalar deleting dtor), etc.
    // But NOT all ?-prefixed names (user C++ functions are also ?-mangled)
    if (name.starts_with("??_") || name.starts_with("?__")) return true;

    static const std::string_view crt_prefixes[] = {
        "std::", "__scrt", "__security", "__GSHandler",
        "__C_specific_handler", "__CxxFrameHandler",
        "Fls", "InitializeCriticalSection", "DeleteCriticalSection",
        "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection",
        "RtlCaptureContext", "RtlLookupFunctionEntry", "RtlVirtualUnwind",
        "memset", "memcpy", "memmove", "memcmp",
        "strcmp", "strlen", "strncmp", "strcpy", "strcat",
        "wcslen", "wcscmp", "wcsncmp",
        "atexit", "exit", "abort",
        "malloc", "free", "realloc", "calloc",
        "operator new", "operator delete",
    };

    for (const auto& prefix : crt_prefixes) {
        if (name.starts_with(prefix)) return true;
    }

    static const std::string_view crt_exact[] = {
        "printf", "fprintf", "sprintf", "snprintf", "vprintf", "vfprintf",
        "puts", "fputs", "fwrite", "fread", "fopen", "fclose", "fflush",
    };

    for (const auto& exact : crt_exact) {
        if (name == exact) return true;
    }

    // MSVC-mangled versions of CRT stdio functions (e.g., _vfprintf_l)
    if (name.starts_with("_v") || name.starts_with("_f") || name.starts_with("_s")) {
        if (name.find("printf") != std::string::npos ||
            name.find("scanf") != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool MapParser::is_export_thunk(ByteView func_code) {
    if (func_code.size() < 2) return true;

    // jmp cs:[rip+disp32] — FF 25 xx xx xx xx (6 bytes)
    if (func_code.size() >= 6 && func_code[0] == 0xFF && func_code[1] == 0x25) {
        return true;
    }

    // REX.W jmp cs:[rip+disp32] — 48 FF 25 xx xx xx xx (7 bytes)
    if (func_code.size() >= 7 && func_code[0] == 0x48 &&
        func_code[1] == 0xFF && func_code[2] == 0x25) {
        return true;
    }

    // call cs:[rip+disp32] — FF 15 xx xx xx xx (6 bytes)
    if (func_code.size() >= 6 && func_code[0] == 0xFF && func_code[1] == 0x15) {
        return true;
    }

    // REX.W call cs:[rip+disp32] — 48 FF 15 xx xx xx xx (7 bytes)
    if (func_code.size() >= 7 && func_code[0] == 0x48 &&
        func_code[1] == 0xFF && func_code[2] == 0x15) {
        return true;
    }

    // jmp rel32 — E9 xx xx xx xx (5 bytes) — tail call thunk
    if (func_code.size() <= 7 && func_code[0] == 0xE9) {
        return true;
    }

    return false;
}

MxResult<MapParseResult> MapParser::parse(const std::filesystem::path& map_path) {
    std::ifstream file(map_path);
    if (!file.is_open()) {
        return std::unexpected(error::io(
            std::format("Cannot open .map file: '{}'", map_path.string())));
    }

    MapParseResult result;
    std::vector<MapSection> sections;

    enum class ParseState {
        header,
        sections,
        symbols,
        done
    };

    auto state = ParseState::header;
    std::string line;
    bool found_publics = false;

    while (std::getline(file, line)) {
        const auto trimmed = trim(line);
        if (trimmed.empty()) continue;

        if (trimmed.find("Preferred load address is") != std::string::npos) {
            const auto pos = trimmed.rfind(' ');
            if (pos != std::string::npos) {
                try {
                    result.image_base = std::stoull(trimmed.substr(pos + 1), nullptr, 16);
                } catch (const std::exception&) {
                    // Malformed "Preferred load address is <hex>" line —
                    // leave image_base at its zero default so downstream
                    // RVA arithmetic surfaces the parse failure loudly
                    // instead of silently misinterpreting the hex.
                    result.image_base = 0;
                }
            }
            continue;
        }

        if (trimmed.find("Start") != std::string::npos &&
            trimmed.find("Length") != std::string::npos &&
            trimmed.find("Name") != std::string::npos) {
            state = ParseState::sections;
            continue;
        }

        if (trimmed.find("Address") != std::string::npos &&
            trimmed.find("Publics by Value") != std::string::npos) {
            state = ParseState::symbols;
            found_publics = true;
            continue;
        }

        if (state == ParseState::sections) {
            // Format: " 0001:00000000 00008xxxH .text$mn                CODE"
            std::istringstream iss(trimmed);
            std::string addr_str, len_str, name_str, cls_str;

            if (!(iss >> addr_str >> len_str >> name_str)) continue;
            iss >> cls_str;

            MapSection sec;
            if (!parse_address(addr_str, sec.index, sec.offset)) continue;

            if (len_str.back() == 'H' || len_str.back() == 'h') {
                len_str.pop_back();
            }
            try {
                sec.length = static_cast<uint32_t>(std::stoul(len_str, nullptr, 16));
            } catch (...) {
                continue;
            }

            sec.name = std::move(name_str);
            sec.cls = std::move(cls_str);
            sections.push_back(sec);
        }

        if (state == ParseState::symbols && found_publics) {
            // Format: " 0001:00000000       func_name   0000000140001000 f   LIBCMT:obj.obj"
            // Flags: 'f' (function), 'i' (imported) appear between RVA and object name
            std::istringstream iss(trimmed);
            std::string addr_str, func_name, rva_str;

            if (!(iss >> addr_str >> func_name >> rva_str)) continue;

            // Skip single-char flag tokens ('f', 'i') to reach the object file name
            std::string obj_str;
            std::string token;
            while (iss >> token) {
                if (token.size() == 1 && (token[0] == 'f' || token[0] == 'i')) {
                    continue;
                }
                obj_str = token;
                break;
            }

            uint32_t sec_idx = 0, offset = 0;
            if (!parse_address(addr_str, sec_idx, offset)) continue;

            if (sec_idx != 1) continue;

            Va rva_base = 0;
            if (!parse_rva_base(rva_str, rva_base)) continue;

            MapFunctionEntry entry;
            entry.name = std::move(func_name);
            entry.rva = static_cast<Rva>(rva_base - result.image_base);
            entry.section_index = sec_idx;
            entry.object_file = trim(obj_str);
            entry.is_library = is_library_object(entry.object_file);

            result.all_functions.push_back(std::move(entry));
        }
    }

    if (result.all_functions.empty()) {
        return std::unexpected(error::io(
            "MapParser: no functions found in .map file"));
    }

    std::ranges::sort(result.all_functions,
        [](const auto& a, const auto& b) { return a.rva < b.rva; });

    // Compute function sizes from RVA gaps
    uint32_t text_end_rva = 0;
    for (const auto& sec : sections) {
        if (sec.index == 1) {
            text_end_rva = sec.offset + sec.length;
            break;
        }
    }

    // Find the base RVA of section 0001 from the first function
    Rva text_base_rva = 0;
    if (!result.all_functions.empty()) {
        // The first function's offset in section should be 0, so its RVA is the section RVA
        // But some functions may start at offset > 0.
        // We use the section info if available, otherwise approximate from first func
        for (const auto& sec : sections) {
            if (sec.index == 1 && sec.offset == 0) {
                text_base_rva = result.all_functions.front().rva;
                break;
            }
        }
    }

    for (size_t i = 0; i < result.all_functions.size(); ++i) {
        if (i + 1 < result.all_functions.size()) {
            result.all_functions[i].size =
                result.all_functions[i + 1].rva - result.all_functions[i].rva;
        } else {
            uint32_t end_rva_abs = text_base_rva + text_end_rva;
            if (end_rva_abs > result.all_functions[i].rva) {
                result.all_functions[i].size =
                    end_rva_abs - result.all_functions[i].rva;
            } else {
                result.all_functions[i].size = 0;
            }
        }
    }

    return result;
}

std::vector<MapFunctionEntry> MapParser::filter_candidates(
    const std::vector<MapFunctionEntry>& functions,
    ByteView pe_code,
    Rva text_rva,
    uint32_t text_size)
{
    std::vector<MapFunctionEntry> candidates;
    candidates.reserve(functions.size() / 2);

    for (const auto& func : functions) {
        if (func.is_library) continue;

        if (is_crt_function_name(func.name)) continue;

        if (func.size < kMinFunctionSize || func.size > kMaxFunctionSize) continue;

        if (func.rva < text_rva || func.rva >= text_rva + text_size) continue;

        const uint32_t offset_in_text = func.rva - text_rva;
        if (offset_in_text + func.size > pe_code.size()) continue;

        ByteView func_code{pe_code.data() + offset_in_text,
                           std::min(static_cast<size_t>(func.size),
                                    pe_code.size() - offset_in_text)};

        if (is_export_thunk(func_code)) continue;

        candidates.push_back(func);
    }

    return candidates;
}

} // namespace mx
