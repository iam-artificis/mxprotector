/**
 * @file cff_function_source.cpp
 * @brief Implementation of the three CFF candidate-discovery sources.
 */

#include "mxprotector/protection/cfg/cff_function_source.hpp"

#include <optional>

#include "mxprotector/core/context.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/protection/cfg/cff_safety_filters.hpp"
#include "mxprotector/protection/cfg/map_parser.hpp"

namespace mx::cff {

std::vector<FunctionCandidate> candidates_from_markers(ProtectionContext& ctx) {
    std::vector<FunctionCandidate> out;
    for (const auto& marker : ctx.markers()) {
        if (marker.type != MarkerType::obfuscate_begin) continue;

        const Rva      start = marker.start_rva;
        const Rva      end   = marker.end_rva;
        const uint32_t size  = end - start;
        if (size < 16) continue;

        ctx.log_fmt("CfgFlatteningPass: регион [0x{:08X}-0x{:08X}] ({} байт)",
            start, end, size);
        out.push_back({start, size});
    }
    return out;
}

std::optional<std::vector<FunctionCandidate>>
candidates_from_map_file(ProtectionContext& ctx) {
    if (ctx.config().map_file_path.empty()) return std::nullopt;

    ctx.log_fmt("CfgFlatteningPass: парсинг .map файла: {}",
        ctx.config().map_file_path.string());

    auto map_result = MapParser::parse(ctx.config().map_file_path);
    if (!map_result) {
        ctx.log_fmt("CfgFlatteningPass: ошибка парсинга .map: {}",
            map_result.error().message());
        return std::nullopt;
    }

    const pe::SectionInfo* text_sec = nullptr;
    for (const auto& s : ctx.pe_image().sections()) {
        if (s.is_code() && s.name == ".text") {
            text_sec = &s;
            break;
        }
    }
    if (!text_sec) return std::vector<FunctionCandidate>{};

    ByteView text_code{text_sec->data.data(), text_sec->data.size()};
    auto     candidates = MapParser::filter_candidates(
        map_result->all_functions, text_code,
        text_sec->virtual_address, text_sec->virtual_size);

    ctx.log_fmt("CfgFlatteningPass: .map: {} функций всего, "
                "{} кандидатов для CFF",
        map_result->all_functions.size(), candidates.size());

    std::vector<FunctionCandidate> out;
    out.reserve(candidates.size());
    for (const auto& func : candidates) {
        out.push_back({func.rva, func.size});
    }
    return out;
}

std::vector<FunctionCandidate> candidates_from_pdata(ProtectionContext& ctx) {
    // `.pdata` fallback: iterate every `RUNTIME_FUNCTION` whose begin
    // address is before the entry point and try to flatten each one.
    // This automatically covers binaries that ship without a `.map`
    // file or `MX_OBFUSCATE_BEGIN/END` markers.
    //
    // ## The old bug
    //
    // An earlier version of this loop flattened every entry in that
    // window unconditionally, which broke C++ binaries on `-l standard`+
    // because a subset of `.pdata` entries describe CODE SLICES, not
    // full functions:
    //
    //   * **`UNW_FLAG_CHAININFO`**: MSVC emits chained unwind records
    //     whenever a function has multiple prologue phases (e.g.,
    //     registers saved lazily after the main prologue). The chained
    //     entry's `BeginAddress`/`EndAddress` cover a slice in the
    //     middle of the parent function; linear execution falls out
    //     of the slice into the parent function's continuation, NOT
    //     to a `ret` inside the slice. CFG flattening on that slice
    //     emits a dispatcher with `jmp exit` for the last block
    //     (exit_label is a one-byte `int3` trap). Runtime execution
    //     hits the trap the moment it reaches the slice through the
    //     parent flow → exit 127 with no stdout during CRT startup.
    //
    //   * **`UNW_FLAG_EHANDLER`** / **`UNW_FLAG_UHANDLER`**: functions
    //     with attached SEH/C++ handlers carry a scope table after
    //     the unwind codes. Flattening their body invalidates the
    //     address references inside the scope table, so the runtime
    //     dispatcher picks the wrong handler (or an invalid one) and
    //     the process aborts.
    //
    // The `test_exception.exe` smoke test used to exit 127 under
    // `-l standard` without `--no-cfg-flattening` because `.pdata[2]`
    // at RVA 0x10C1 was a chained entry (parent at 0x1070) that this
    // loop flattened. `dumpbin /UNWINDINFO` confirmed the CHAININFO
    // flag.
    //
    // ## The fix
    //
    // Skip any entry whose `UNWIND_INFO.Flags` contains any of
    // EHANDLER / UHANDLER / CHAININFO. This leaves normal leaf
    // functions and standard-prologue functions eligible for CFF
    // while excluding the slice-style chained entries and the
    // SEH-bearing functions that carry language-specific scope
    // tables. The filter is cheap (one byte read per candidate) and
    // has no runtime cost in the protected binary.
    ctx.log("CfgFlatteningPass: используем .pdata для границ функций");

    struct RuntimeFunction {
        uint32_t begin_addr;
        uint32_t end_addr;
        uint32_t unwind_info;
    };

    const pe::SectionInfo* pdata = ctx.pe_image().section_by_name(".pdata");
    if (!pdata || pdata->data.size() < sizeof(RuntimeFunction)) {
        ctx.log("CfgFlatteningPass: .pdata не найдена, пропуск CFF");
        return {};
    }

    const size_t func_count = pdata->data.size() / sizeof(RuntimeFunction);
    const auto*  funcs      = reinterpret_cast<const RuntimeFunction*>(pdata->data.data());

    ctx.log_fmt("CfgFlatteningPass: найдено {} функций в .pdata", func_count);

    const Rva    entry_rva = ctx.pe_image().entry_point_rva();
    size_t       entry_idx = func_count;
    for (size_t j = 0; j < func_count; ++j) {
        if (funcs[j].begin_addr <= entry_rva && funcs[j].end_addr > entry_rva) {
            entry_idx = j;
            break;
        }
    }

    ctx.log_fmt("CfgFlatteningPass: entry point at .pdata[{}] "
                "(RVA=0x{:08X}), CFF range: [0..{})",
        entry_idx, entry_rva, entry_idx);

    std::vector<FunctionCandidate> out;
    out.reserve(entry_idx);

    uint32_t unsafe_skipped = 0;
    for (size_t i = 0; i < entry_idx; ++i) {
        const Rva      func_rva  = funcs[i].begin_addr;
        const uint32_t func_size = funcs[i].end_addr - funcs[i].begin_addr;

        if (func_size < MapParser::kMinFunctionSize ||
            func_size > MapParser::kMaxFunctionSize) continue;

        if (unwind_info_makes_function_unsafe(
                ctx.pe_image(), funcs[i].unwind_info)) {
            ++unsafe_skipped;
            continue;
        }

        out.push_back({func_rva, func_size});
    }

    if (unsafe_skipped > 0) {
        ctx.log_fmt("CfgFlatteningPass: пропущено {} функций с "
                    "UNW_FLAG_EHANDLER/UHANDLER/CHAININFO "
                    "(compat с C++ exception unwinder + "
                    "chained-unwind slices)",
            unsafe_skipped);
    }

    return out;
}

namespace {

/// Obfuscate markers win the strategy race even if every individual
/// region is later filtered out by size. Matches the original code's
/// "markers present → lock the path" semantic.
[[nodiscard]] bool has_obfuscate_markers(const ProtectionContext& ctx) noexcept {
    for (const auto& m : ctx.markers()) {
        if (m.type == MarkerType::obfuscate_begin) return true;
    }
    return false;
}

} // namespace

std::vector<FunctionCandidate> gather_candidates(ProtectionContext& ctx) {
    if (has_obfuscate_markers(ctx)) {
        return candidates_from_markers(ctx);
    }

    // `.map` only gates the fall-through when parsing actually
    // succeeded — a missing path or parse error is indistinguishable
    // from "user never asked for a map file" and we drop into `.pdata`.
    // A successful-but-empty parse blocks `.pdata`: if the user wired
    // up a `.map` and it had no CFF-eligible functions, honour that.
    if (auto from_map = candidates_from_map_file(ctx)) {
        return std::move(*from_map);
    }
    return candidates_from_pdata(ctx);
}

} // namespace mx::cff
