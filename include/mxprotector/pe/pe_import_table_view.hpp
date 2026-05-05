/**
 * @file pe_import_table_view.hpp
 * @brief PE-side implementation of `target::IImportTableView`.
 *
 * @details Wraps a `PeImage&` and projects its `imports()` vector into
 *          the read-only `target::IImportTableView` shape. Indices are
 *          identical to positions in the underlying `imports()` vector
 *          (DLL index) and `imports()[i].functions` (function index),
 *          so the wrapper is allocation-free at construction time and
 *          O(1) for every accessor.
 *
 *          Lifetime: the view borrows the `PeImage` through a
 *          reference and must not outlive it. In practice the view is
 *          a member of `PeImageBinaryAdapter`, which is itself owned
 *          by `ProtectionContext` alongside the wrapped `PeImage`.
 */

#pragma once

#include <cstddef>
#include <string_view>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/target/binary_capabilities.hpp"

namespace mx::pe {

/// `target::IImportTableView` adapter over `mx::PeImage::imports()`.
class PeImportTableView final : public target::IImportTableView {
public:
    explicit PeImportTableView(const PeImage& image) noexcept
        : image_(image) {}

    [[nodiscard]] std::size_t dll_count() const noexcept override {
        return image_.imports().size();
    }

    [[nodiscard]] std::string_view
    dll_name(std::size_t dll_index) const noexcept override {
        const auto& imports = image_.imports();
        if (dll_index >= imports.size()) return {};
        return imports[dll_index].dll_name;
    }

    [[nodiscard]] std::size_t
    function_count(std::size_t dll_index) const noexcept override {
        const auto& imports = image_.imports();
        if (dll_index >= imports.size()) return 0;
        return imports[dll_index].functions.size();
    }

    [[nodiscard]] std::string_view
    function_name(std::size_t dll_index,
                  std::size_t fn_index) const noexcept override {
        const auto* fn = lookup_fn(dll_index, fn_index);
        if (!fn || fn->by_ordinal) return {};
        return fn->name;
    }

    [[nodiscard]] Rva
    function_thunk_rva(std::size_t dll_index,
                       std::size_t fn_index) const noexcept override {
        const auto* fn = lookup_fn(dll_index, fn_index);
        return fn ? fn->thunk_rva : Rva{0};
    }

private:
    [[nodiscard]] const ImportFunction*
    lookup_fn(std::size_t dll_index,
              std::size_t fn_index) const noexcept {
        const auto& imports = image_.imports();
        if (dll_index >= imports.size()) return nullptr;
        const auto& fns = imports[dll_index].functions;
        if (fn_index >= fns.size()) return nullptr;
        return &fns[fn_index];
    }

    const PeImage& image_;
};

} // namespace mx::pe
