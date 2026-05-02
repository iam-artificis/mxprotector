/**
 * @file main_helpers.hpp
 * @brief Helpers extracted from `main.cpp` (R5.1).
 *
 * `main.cpp` used to bundle the orchestration body together with
 * five small free helpers (file I/O, ISO timestamp, trace-hints
 * sidecar emission, console summary, section-role lookup). The
 * orchestration is the only thing that needs to live next to
 * `main()`; everything else is independently testable and
 * reusable, so R5.1 lifts them into this header + a sibling cpp.
 *
 * No new behaviour — every function below is a verbatim move from
 * the previous in-line body.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"

namespace mx {
class ProtectionContext;
struct ProtectionConfig;
struct SectionNameMap;
}

namespace mx::cli {

/// Read the entire contents of @p path into a `ByteBuffer`.
[[nodiscard]] MxResult<ByteBuffer> read_file(const std::filesystem::path& path);

/// Write @p data to @p path, creating parent directories on demand.
[[nodiscard]] MxStatus write_file(const std::filesystem::path& path,
                                   ByteView                     data);

/// `YYYY-MM-DDThh:mm:ssZ` UTC timestamp of "now".
[[nodiscard]] std::string iso8601_utc_now();

/// Map a section name back to its logical role for the trace-hints
/// sidecar. MxProtector-added sections look up against the
/// per-build pool; pre-existing sections keep their literal name.
[[nodiscard]] std::string_view section_role_for(
    const std::string&    section_name,
    const SectionNameMap& names);

/// Write `<output>.mxtrace.json` next to the protected PE.
[[nodiscard]] MxStatus write_trace_hints_sidecar(
    const std::filesystem::path& output_pe_path,
    std::string_view             json);

/// Console summary block printed at the end of every successful run.
void print_summary(const ProtectionConfig&  config,
                   const ProtectionContext& ctx,
                   std::size_t              input_size,
                   std::size_t              output_size,
                   std::int64_t             elapsed_ms);

} // namespace mx::cli
