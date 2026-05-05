/**
 * @file pe_image_binary_adapter.hpp
 * @brief Adapter that lets `PeImage` satisfy the `target::IBinaryImage`
 *        contract.
 *
 * @details `IBinaryImage` (declared in `target/binary_image.hpp`) is
 *          the format-agnostic seam every container-aware-but-not-
 *          PE-bound pass should be talking to. `PeImage`'s public
 *          API uses richer, PE-specific signatures (`SectionInfo`,
 *          `add_section(SectionInfo)`, etc.) that don't line up with
 *          the interface — direct inheritance would conflict on
 *          method signature.
 *
 *          This adapter wraps a `PeImage&` and translates between
 *          the two views:
 *
 *            * `PeImage::sections()` (`vector<SectionInfo>&`) ↔
 *              `IBinaryImage::sections()` (`vector<SectionView>` by
 *              value).
 *            * `PeImage::section_by_name()` (`const SectionInfo*`) ↔
 *              `IBinaryImage::find_section()` (`MxResult<SectionView>`).
 *            * `PeImage::add_section(SectionInfo)` ↔
 *              `IBinaryImage::add_section(name, data, flags)` — adapter
 *              builds a `SectionInfo` from the (name, data, flags)
 *              triple and forwards.
 *            * IMAGE_SCN_MEM_* characteristics ↔ `target::SectionFlags`.
 *
 *          The adapter is owned by `ProtectionContext` and exposed
 *          via `ProtectionContext::binary_image()`. Existing PE-aware
 *          passes keep using `PeImage&` directly; new container-
 *          agnostic passes (and ELF / Mach-O passes when those land)
 *          read through `IBinaryImage&` and pick up the right
 *          implementation automatically.
 */

#pragma once

#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/target/binary_image.hpp"
#include "mxprotector/target/target_info.hpp"

namespace mx::pe {

/**
 * @brief `target::IBinaryImage` view over a `mx::PeImage`.
 *
 * @details Holds a non-owning reference to a `PeImage` plus a copy
 *          of the build's `TargetInfo` (so `target()` answers without
 *          re-deriving from PE state every call). Construction is
 *          cheap; mutations forward through to the wrapped
 *          `PeImage`.
 *
 *          Thread-safety: the adapter inherits the underlying
 *          `PeImage`'s single-threaded ownership semantics — both
 *          live inside `ProtectionContext`, which is mutated single-
 *          threaded by the pass manager.
 */
class PeImageBinaryAdapter final : public target::IBinaryImage {
public:
    PeImageBinaryAdapter(PeImage& image, target::TargetInfo info) noexcept
        : image_(image), info_(info) {}

    [[nodiscard]] target::TargetInfo target() const noexcept override { return info_; }
    [[nodiscard]] uint64_t           image_base() const noexcept override { return image_.image_base(); }
    [[nodiscard]] Rva                entry_point_rva() const noexcept override { return image_.entry_point_rva(); }
    void                              set_entry_point_rva(Rva rva) override { image_.set_entry_point_rva(rva); }
    [[nodiscard]] bool               is_64bit() const noexcept override { return image_.is_64bit(); }

    [[nodiscard]] std::vector<target::SectionView> sections() const override;

    [[nodiscard]] MxResult<target::SectionView>
    find_section(std::string_view name) const override;

    [[nodiscard]] MxResult<uint32_t>
    add_section(std::string_view name, ByteView data,
                target::SectionFlags flags) override;

    [[nodiscard]] MxStatus
    patch_section_bytes(uint32_t section_index, uint32_t offset,
                        ByteView data) override;

    /// Update the cached `TargetInfo` — used when `ProtectionContext`
    /// learns the load mode (CLI flag) after construction.
    void set_target(target::TargetInfo info) noexcept { info_ = info; }

private:
    PeImage&            image_;
    target::TargetInfo  info_;
};

} // namespace mx::pe
