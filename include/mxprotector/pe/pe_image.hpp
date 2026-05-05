/**
 * @file pe_image.hpp
 * @brief [BUILDER] Central PE-image class — full high-level view of a PE file.
 *
 * @details `PeImage` owns every component of a parsed PE binary: raw
 *          file bytes, DOS / NT headers (variant PE32 / PE32+), the
 *          section table, imports, exports, relocations, and image
 *          metadata (entry point, base, alignments). It also provides
 *          RVA ↔ file-offset conversion, section navigation by name
 *          or RVA, byte read / write by RVA, and section addition.
 *
 * @note    NT headers live in a `std::variant<IMAGE_NT_HEADERS32,
 *          IMAGE_NT_HEADERS64>` so the same class handles both PE32
 *          and PE32+ without subclassing. PE types are vendored under
 *          `mxprotector/pe/types/`, so the class never depends on
 *          `<windows.h>`.
 *
 *          SOLID: SRP — `PeImage` only stores parsed state and
 *          provides navigation. Parsing (`PeParser`), serialization
 *          (`PeBuilder`), section management (`SectionManager`), and
 *          per-table editors (`ImportTableManager`, …) live in
 *          dedicated classes.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <variant>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx {

/**
 * @brief Round @p value up to the nearest multiple of @p alignment.
 * @param value      Value to align.
 * @param alignment  Alignment (must be a power of two).
 * @return           Aligned value.
 */
[[nodiscard]] constexpr uint64_t align_up(uint64_t value, uint64_t alignment) noexcept {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

/**
 * @brief Полное высокоуровневое представление PE-файла.
 *
 * Создаётся через `PeParser::parse()`, собирается через
 * `PeBuilder::build()`. Все мутации идут через сеттеры или прямые
 * ссылки на изменяемые поля (sections, imports, exports, relocations).
 */
class PeImage {
public:
    /// Variant of NT headers (PE32 vs PE32+) — picked by `Machine`.
    using NtHeaders = std::variant<pe::IMAGE_NT_HEADERS32, pe::IMAGE_NT_HEADERS64>;

    PeImage() = default;
    ~PeImage() = default;

    PeImage(PeImage&&) noexcept = default;
    PeImage& operator=(PeImage&&) noexcept = default;
    PeImage(const PeImage&) = default;
    PeImage& operator=(const PeImage&) = default;

    // ====================================================================
    // Основные свойства
    // ====================================================================

    /// @brief True for PE32+ (x64), false for PE32 (x86).
    [[nodiscard]] bool is_64bit() const noexcept { return arch_ == Architecture::x64; }

    /// @brief Architecture of the parsed image.
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

    /// @brief PE file kind (executable / dynamic_library / kernel_driver).
    [[nodiscard]] PeType pe_type() const noexcept { return type_; }

    /// @brief RVA of the entry point.
    [[nodiscard]] Rva entry_point_rva() const noexcept { return entry_point_rva_; }

    /// @brief Preferred image base.
    [[nodiscard]] Va image_base() const noexcept { return image_base_; }

    /// @brief File alignment (on-disk section padding).
    [[nodiscard]] uint32_t file_alignment() const noexcept { return file_alignment_; }

    /// @brief Section alignment (in-memory section padding).
    [[nodiscard]] uint32_t section_alignment() const noexcept { return section_alignment_; }

    // ====================================================================
    // Заголовки
    // ====================================================================

    /// @brief Read-only DOS header.
    [[nodiscard]] const pe::IMAGE_DOS_HEADER& dos_header() const noexcept { return dos_header_; }

    /// @brief Mutable DOS header.
    [[nodiscard]] pe::IMAGE_DOS_HEADER& dos_header() noexcept { return dos_header_; }

    /// @brief Read-only NT headers (variant PE32 / PE32+).
    [[nodiscard]] const NtHeaders& nt_headers() const noexcept { return nt_headers_; }

    /// @brief Mutable NT headers.
    [[nodiscard]] NtHeaders& nt_headers() noexcept { return nt_headers_; }

    // ====================================================================
    // Секции
    // ====================================================================

    /// @brief Read-only sections.
    [[nodiscard]] const std::vector<pe::SectionInfo>& sections() const noexcept { return sections_; }

    /// @brief Mutable sections.
    [[nodiscard]] std::vector<pe::SectionInfo>& sections() noexcept { return sections_; }

    /// @brief Find the section containing @p rva, or `nullptr`.
    [[nodiscard]] const pe::SectionInfo* section_by_rva(Rva rva) const noexcept;

    /// @brief Find a section by name (e.g. ".text"), or `nullptr`.
    [[nodiscard]] const pe::SectionInfo* section_by_name(std::string_view name) const noexcept;

    /**
     * @brief Append a new section to the image.
     * @param section  Section to append (raw bytes + characteristics).
     * @return         Index of the new section, or an error if the
     *                 section table can no longer hold an entry
     *                 (96-section hard cap).
     */
    [[nodiscard]] MxResult<uint32_t> add_section(pe::SectionInfo section);

    // ====================================================================
    // Импорты / Экспорты / Релокации
    // ====================================================================

    /// @brief Read-only imports.
    [[nodiscard]] const std::vector<pe::ImportEntry>& imports() const noexcept { return imports_; }
    /// @brief Mutable imports.
    [[nodiscard]] std::vector<pe::ImportEntry>& imports() noexcept { return imports_; }

    /// @brief Read-only export table.
    [[nodiscard]] const pe::ExportTable& exports() const noexcept { return exports_; }
    /// @brief Mutable export table.
    [[nodiscard]] pe::ExportTable& exports() noexcept { return exports_; }

    /// @brief Read-only base-relocation blocks.
    [[nodiscard]] const std::vector<pe::RelocationBlock>& relocations() const noexcept { return relocations_; }
    /// @brief Mutable base-relocation blocks.
    [[nodiscard]] std::vector<pe::RelocationBlock>& relocations() noexcept { return relocations_; }

    // ====================================================================
    // Конвертация адресов / чтение байтов
    // ====================================================================

    /// @brief Convert @p rva to its on-disk file offset, or error.
    [[nodiscard]] MxResult<FileOffset> rva_to_offset(Rva rva) const;

    /// @brief Convert an on-disk @p offset to its RVA, or error.
    [[nodiscard]] MxResult<Rva> offset_to_rva(FileOffset offset) const;

    /// @brief Borrow @p size bytes starting at @p rva from the raw image.
    [[nodiscard]] MxResult<ByteView> read_bytes(Rva rva, size_t size) const;

    /// @brief Overwrite @p data.size() bytes at @p rva in the raw image.
    [[nodiscard]] MxStatus write_bytes(Rva rva, ByteView data);

    // ====================================================================
    // Сырые данные
    // ====================================================================

    /// @brief Read-only view over the underlying raw byte buffer.
    [[nodiscard]] ByteView raw_data() const noexcept {
        return ByteView{raw_data_.data(), raw_data_.size()};
    }

    /// @brief Mutable owning byte buffer (used by serializers).
    [[nodiscard]] ByteBuffer& raw_data_buffer() noexcept { return raw_data_; }

    /// @brief Read-only owning byte buffer.
    [[nodiscard]] const ByteBuffer& raw_data_buffer() const noexcept { return raw_data_; }

    // ====================================================================
    // Setters (used by `PeParser` while building the `PeImage`)
    // ====================================================================

    void set_raw_data(ByteBuffer data)                     { raw_data_ = std::move(data); }
    void set_architecture(Architecture arch)      noexcept { arch_ = arch; }
    void set_pe_type(PeType type)                 noexcept { type_ = type; }
    void set_dos_header(const pe::IMAGE_DOS_HEADER& hdr) noexcept { dos_header_ = hdr; }
    void set_nt_headers(NtHeaders hdrs)                    { nt_headers_ = std::move(hdrs); }
    void set_sections(std::vector<pe::SectionInfo> secs)   { sections_ = std::move(secs); }
    void set_imports(std::vector<pe::ImportEntry> imps)    { imports_ = std::move(imps); }
    void set_exports(pe::ExportTable exp)                  { exports_ = std::move(exp); }
    void set_relocations(std::vector<pe::RelocationBlock> relocs) { relocations_ = std::move(relocs); }
    void set_entry_point_rva(Rva rva)             noexcept { entry_point_rva_ = rva; }
    void set_image_base(Va base)                  noexcept { image_base_ = base; }
    void set_file_alignment(uint32_t align)       noexcept { file_alignment_ = align; }
    void set_section_alignment(uint32_t align)    noexcept { section_alignment_ = align; }

private:
    ByteBuffer                        raw_data_;

    Architecture                      arch_              = Architecture::x64;
    PeType                            type_              = PeType::executable;

    pe::IMAGE_DOS_HEADER              dos_header_{};
    NtHeaders                         nt_headers_;

    std::vector<pe::SectionInfo>      sections_;
    std::vector<pe::ImportEntry>      imports_;
    pe::ExportTable                   exports_;
    std::vector<pe::RelocationBlock>  relocations_;

    Rva                               entry_point_rva_   = 0;
    Va                                image_base_        = 0;
    uint32_t                          file_alignment_    = 0x200;
    uint32_t                          section_alignment_ = 0x1000;
};

// ============================================================================
// Tiny inline accessors (kept here so callers stay free of an extra TU).
// ============================================================================

inline const pe::SectionInfo* PeImage::section_by_rva(Rva rva) const noexcept {
    for (const auto& sec : sections_) {
        if (sec.contains_rva(rva)) {
            return &sec;
        }
    }
    return nullptr;
}

inline const pe::SectionInfo* PeImage::section_by_name(std::string_view name) const noexcept {
    for (const auto& sec : sections_) {
        if (sec.name == name) {
            return &sec;
        }
    }
    return nullptr;
}

} // namespace mx
