/**
 * @file binary_capabilities.hpp
 * @brief Narrow capability views on top of `target::IBinaryImage`.
 *
 * @details `IBinaryImage` describes the operations every container has
 *          (sections, image base, entry point). Some passes need access
 *          to container-specific tables — packer wants the import
 *          table, guard wants the TLS callback list — that don't apply
 *          to every format identically. Putting those on the core
 *          `IBinaryImage` interface would (a) bloat the interface and
 *          (b) force every future container (ELF, Mach-O) to declare
 *          a meaningless impl for tables it doesn't model the same
 *          way (e.g. ELF's PLT/GOT instead of PE's IAT).
 *
 *          `binary_capabilities.hpp` defines the narrower contracts
 *          (`IImportTableView`, future `ITlsTableView`,
 *          `IRelocationTable`, ...). `IBinaryImage` exposes them via
 *          capability accessors — pointer/null when the container
 *          implements / doesn't implement the capability.
 *
 *          Read-only by design — capability views are observation
 *          surfaces. Mutation goes through the existing `PeImage`
 *          editor classes (`ImportTableManager`, `TlsCallbackInjector`
 *          etc.) until those are refactored to live behind their own
 *          mutating capability interfaces in a follow-up branch.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "mxprotector/core/types.hpp"

namespace mx::target {

/**
 * @brief Read-only view of a container's import table (PE) or
 *        equivalent dynamic-symbol table (ELF PLT/GOT, Mach-O lazy
 *        binding).
 *
 * Today only the PE adapter implements this. Future ELF adapter will
 * model PLT entries the same way — same shape, same iteration
 * pattern, different byte format under the hood.
 *
 * Indexing is two-level: `dll_index` over imported libraries,
 * `function_index` within a library. Strings are returned as
 * `string_view` borrowed from the adapter; the adapter outlives any
 * pass that consumes the view.
 *
 * Thread-safety: same as `IBinaryImage` — single-threaded use,
 * inherits ownership semantics from the parent image.
 */
class IImportTableView {
public:
    virtual ~IImportTableView() = default;

    /// Number of imported DLLs / shared objects.
    [[nodiscard]] virtual std::size_t dll_count() const noexcept = 0;

    /// Name of the DLL at @p dll_index. Returns empty view on out-of-range.
    [[nodiscard]] virtual std::string_view
        dll_name(std::size_t dll_index) const noexcept = 0;

    /// Number of functions imported from the DLL at @p dll_index.
    /// Returns 0 on out-of-range.
    [[nodiscard]] virtual std::size_t
        function_count(std::size_t dll_index) const noexcept = 0;

    /// Name of the function at (dll_index, fn_index). Returns empty
    /// view on out-of-range or for ordinal-only imports.
    [[nodiscard]] virtual std::string_view
        function_name(std::size_t dll_index,
                      std::size_t fn_index) const noexcept = 0;

    /// IAT (or equivalent) thunk RVA the loader writes to after
    /// resolving the import. Returns 0 on out-of-range.
    [[nodiscard]] virtual Rva
        function_thunk_rva(std::size_t dll_index,
                           std::size_t fn_index) const noexcept = 0;
};

} // namespace mx::target
