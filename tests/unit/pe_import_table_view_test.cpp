/**
 * @file pe_import_table_view_test.cpp
 * @brief Unit tests for `pe::PeImportTableView` and the
 *        `target::IImportTableView` capability accessor on
 *        `PeImageBinaryAdapter`.
 *
 * @details Confirms:
 *            * `dll_count` matches the number of `ImportEntry`s.
 *            * `dll_name` returns the right name and an empty view for
 *              out-of-range indices.
 *            * `function_count` matches the per-DLL function vector.
 *            * `function_name` returns empty for out-of-range and for
 *              ordinal-only imports.
 *            * `function_thunk_rva` returns the IAT thunk RVA and 0
 *              for out-of-range.
 *            * `IBinaryImage::import_table()` on the PE adapter
 *              returns a non-null pointer to the same view, so
 *              container-agnostic consumers can read imports without
 *              touching `PeImage`.
 */

#include <gtest/gtest.h>

#include <cstdint>

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_image_binary_adapter.hpp"
#include "mxprotector/pe/pe_import_table_view.hpp"
#include "mxprotector/pe/pe_types.hpp"
#include "mxprotector/target/binary_capabilities.hpp"
#include "mxprotector/target/target_info.hpp"

using namespace mx;
using namespace mx::pe;
using namespace mx::target;

namespace {

PeImage make_image_with_imports() {
    PeImage img;
    img.set_architecture(Architecture::x64);
    img.set_image_base(0x140000000ULL);

    ImportEntry kernel32;
    kernel32.dll_name        = "kernel32.dll";
    kernel32.descriptor_rva  = 0x3000;
    {
        ImportFunction f;
        f.name      = "GetProcAddress";
        f.thunk_rva = 0x3100;
        kernel32.functions.push_back(f);
    }
    {
        ImportFunction f;
        f.name      = "LoadLibraryA";
        f.thunk_rva = 0x3108;
        kernel32.functions.push_back(f);
    }

    ImportEntry user32;
    user32.dll_name       = "user32.dll";
    user32.descriptor_rva = 0x3200;
    {
        ImportFunction f;
        f.by_ordinal = true;
        f.ordinal    = 17;
        f.thunk_rva  = 0x3300;
        user32.functions.push_back(f);
    }

    img.set_imports({std::move(kernel32), std::move(user32)});
    return img;
}

TargetInfo windows_pe_x64_info() {
    return TargetInfo::windows_pe_x64();
}

} // namespace

TEST(PeImportTableView, DllCountMatchesImports) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_EQ(view.dll_count(), 2u);
}

TEST(PeImportTableView, DllNameReturnsRightStrings) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_EQ(view.dll_name(0), "kernel32.dll");
    EXPECT_EQ(view.dll_name(1), "user32.dll");
}

TEST(PeImportTableView, DllNameOutOfRangeIsEmpty) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_TRUE(view.dll_name(2).empty());
    EXPECT_TRUE(view.dll_name(99).empty());
}

TEST(PeImportTableView, FunctionCountPerDll) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_EQ(view.function_count(0), 2u);
    EXPECT_EQ(view.function_count(1), 1u);
    EXPECT_EQ(view.function_count(99), 0u);
}

TEST(PeImportTableView, FunctionNameAndThunkRva) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_EQ(view.function_name(0, 0), "GetProcAddress");
    EXPECT_EQ(view.function_name(0, 1), "LoadLibraryA");
    EXPECT_EQ(view.function_thunk_rva(0, 0), 0x3100u);
    EXPECT_EQ(view.function_thunk_rva(0, 1), 0x3108u);
}

TEST(PeImportTableView, OrdinalImportHasEmptyName) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_TRUE(view.function_name(1, 0).empty());
    EXPECT_EQ(view.function_thunk_rva(1, 0), 0x3300u);
}

TEST(PeImportTableView, OutOfRangeFunctionAccessFailsCleanly) {
    auto img = make_image_with_imports();
    PeImportTableView view(img);
    EXPECT_TRUE(view.function_name(0, 99).empty());
    EXPECT_EQ(view.function_thunk_rva(0, 99), 0u);
    EXPECT_TRUE(view.function_name(99, 0).empty());
    EXPECT_EQ(view.function_thunk_rva(99, 0), 0u);
}

TEST(PeImageBinaryAdapter, ImportTableCapabilityReturnsNonNull) {
    auto img = make_image_with_imports();
    PeImageBinaryAdapter adapter(img, windows_pe_x64_info());

    const IImportTableView* import_view = adapter.import_table();
    ASSERT_NE(import_view, nullptr);
    EXPECT_EQ(import_view->dll_count(), 2u);
    EXPECT_EQ(import_view->dll_name(0), "kernel32.dll");
    EXPECT_EQ(import_view->function_thunk_rva(0, 0), 0x3100u);
}

TEST(PeImageBinaryAdapter, ImportTableViewLifetimeMatchesAdapter) {
    auto img = make_image_with_imports();
    PeImageBinaryAdapter adapter(img, windows_pe_x64_info());

    const IImportTableView* a = adapter.import_table();
    const IImportTableView* b = adapter.import_table();
    EXPECT_EQ(a, b);
}
