/**
 * @file pe_image.hpp
 * @brief [BUILDER] Центральный класс PeImage — полное высокоуровневое представление PE-файла.
 *
 * @details PeImage инкапсулирует всё содержимое PE: сырые данные файла, заголовки DOS/NT,
 *          таблицу секций, импорты, экспорты, релокации и метаданные.
 *          Обеспечивает конвертацию RVA ↔ FileOffset, навигацию по секциям,
 *          чтение/запись байтов по RVA, добавление новых секций.
 *          Является основной единицей работы для всех модулей BUILDER.
 *
 * @note NT-заголовки хранятся в std::variant<IMAGE_NT_HEADERS32, IMAGE_NT_HEADERS64>.
 *       Архитектура определяется по полю Machine в FILE_HEADER при парсинге.
 *       PeImage не зависит от Windows.h — все PE-типы определены в pe_types.hpp.
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <variant>
#include <algorithm>
#include <ranges>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/pe/pe_types.hpp"

namespace mx {

/**
 * @brief Выравнивает значение вверх до кратного alignment.
 * @param value Исходное значение.
 * @param alignment Выравнивание (должно быть степенью двойки).
 * @return Выровненное значение.
 */
[[nodiscard]] constexpr uint64_t align_up(uint64_t value, uint64_t alignment) noexcept {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

/**
 * @brief Полное высокоуровневое представление PE-файла.
 *
 * @details Хранит все разобранные компоненты PE-образа и предоставляет
 *          API для навигации, модификации и подготовки к сборке.
 *          Создаётся через PeParser::parse(), собирается через PeBuilder::build().
 *
 *          SOLID: SRP — PeImage только хранит данные и предоставляет базовую навигацию.
 *          Парсинг (PeParser), сборка (PeBuilder), управление секциями (SectionManager)
 *          и таблицами (ImportTableManager и т.д.) вынесены в отдельные классы.
 */
class PeImage {
public:
    /// @brief Тип для хранения NT-заголовков (PE32 или PE32+).
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

    /**
     * @brief Проверяет, является ли образ 64-битным (PE32+).
     * @return true для x64, false для x86.
     */
    [[nodiscard]] bool is_64bit() const noexcept { return arch_ == Architecture::x64; }

    /**
     * @brief Возвращает архитектуру PE-файла.
     * @return Architecture::x86 или Architecture::x64.
     */
    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

    /**
     * @brief Возвращает тип PE-файла (exe/dll/sys).
     * @return PeType.
     */
    [[nodiscard]] PeType pe_type() const noexcept { return type_; }

    /**
     * @brief Возвращает RVA точки входа.
     * @return RVA entry point.
     */
    [[nodiscard]] Rva entry_point_rva() const noexcept { return entry_point_rva_; }

    /**
     * @brief Возвращает предпочтительную базу загрузки образа.
     * @return Виртуальный адрес базы.
     */
    [[nodiscard]] Va image_base() const noexcept { return image_base_; }

    /**
     * @brief Возвращает выравнивание секций на диске.
     * @return Выравнивание файла в байтах.
     */
    [[nodiscard]] uint32_t file_alignment() const noexcept { return file_alignment_; }

    /**
     * @brief Возвращает выравнивание секций в памяти.
     * @return Выравнивание секций в байтах.
     */
    [[nodiscard]] uint32_t section_alignment() const noexcept { return section_alignment_; }

    // ====================================================================
    // Заголовки
    // ====================================================================

    /**
     * @brief Возвращает константную ссылку на DOS-заголовок.
     * @return Константная ссылка на IMAGE_DOS_HEADER.
     */
    [[nodiscard]] const pe::IMAGE_DOS_HEADER& dos_header() const noexcept { return dos_header_; }

    /**
     * @brief Возвращает изменяемую ссылку на DOS-заголовок.
     * @return Ссылка на IMAGE_DOS_HEADER.
     */
    [[nodiscard]] pe::IMAGE_DOS_HEADER& dos_header() noexcept { return dos_header_; }

    /**
     * @brief Возвращает константную ссылку на NT-заголовки (variant PE32/PE32+).
     * @return Константная ссылка на NtHeaders.
     */
    [[nodiscard]] const NtHeaders& nt_headers() const noexcept { return nt_headers_; }

    /**
     * @brief Возвращает изменяемую ссылку на NT-заголовки.
     * @return Ссылка на NtHeaders.
     */
    [[nodiscard]] NtHeaders& nt_headers() noexcept { return nt_headers_; }

    // ====================================================================
    // Секции
    // ====================================================================

    /**
     * @brief Возвращает константный список секций.
     * @return Константная ссылка на вектор SectionInfo.
     */
    [[nodiscard]] const std::vector<pe::SectionInfo>& sections() const noexcept { return sections_; }

    /**
     * @brief Возвращает изменяемый список секций.
     * @return Ссылка на вектор SectionInfo.
     */
    [[nodiscard]] std::vector<pe::SectionInfo>& sections() noexcept { return sections_; }

    /**
     * @brief Ищет секцию, содержащую указанный RVA.
     * @param rva Относительный виртуальный адрес для поиска.
     * @return Указатель на SectionInfo или nullptr, если секция не найдена.
     */
    [[nodiscard]] const pe::SectionInfo* section_by_rva(Rva rva) const noexcept;

    /**
     * @brief Ищет секцию по имени.
     * @param name Имя секции (например, ".text").
     * @return Указатель на SectionInfo или nullptr, если секция не найдена.
     */
    [[nodiscard]] const pe::SectionInfo* section_by_name(std::string_view name) const noexcept;

    /**
     * @brief Добавляет новую секцию в образ.
     * @param section Информация о добавляемой секции (имя, данные, характеристики).
     * @return Индекс добавленной секции или ошибка при нехватке места в заголовках.
     */
    [[nodiscard]] MxResult<uint32_t> add_section(pe::SectionInfo section);

    // ====================================================================
    // Импорты / Экспорты / Релокации
    // ====================================================================

    /**
     * @brief Возвращает константный список импортируемых DLL.
     * @return Константная ссылка на вектор ImportEntry.
     */
    [[nodiscard]] const std::vector<pe::ImportEntry>& imports() const noexcept { return imports_; }

    /**
     * @brief Возвращает изменяемый список импортируемых DLL.
     * @return Ссылка на вектор ImportEntry.
     */
    [[nodiscard]] std::vector<pe::ImportEntry>& imports() noexcept { return imports_; }

    /**
     * @brief Возвращает константную таблицу экспортов.
     * @return Константная ссылка на ExportTable.
     */
    [[nodiscard]] const pe::ExportTable& exports() const noexcept { return exports_; }

    /**
     * @brief Возвращает изменяемую таблицу экспортов.
     * @return Ссылка на ExportTable.
     */
    [[nodiscard]] pe::ExportTable& exports() noexcept { return exports_; }

    /**
     * @brief Возвращает константный список блоков релокаций.
     * @return Константная ссылка на вектор RelocationBlock.
     */
    [[nodiscard]] const std::vector<pe::RelocationBlock>& relocations() const noexcept { return relocations_; }

    /**
     * @brief Возвращает изменяемый список блоков релокаций.
     * @return Ссылка на вектор RelocationBlock.
     */
    [[nodiscard]] std::vector<pe::RelocationBlock>& relocations() noexcept { return relocations_; }

    // ====================================================================
    // Конвертация адресов
    // ====================================================================

    /**
     * @brief Конвертирует RVA в файловое смещение.
     * @param rva Относительный виртуальный адрес.
     * @return Файловое смещение или ошибка, если RVA не принадлежит ни одной секции.
     */
    [[nodiscard]] MxResult<FileOffset> rva_to_offset(Rva rva) const;

    /**
     * @brief Конвертирует файловое смещение в RVA.
     * @param offset Смещение от начала файла.
     * @return RVA или ошибка, если смещение не принадлежит ни одной секции.
     */
    [[nodiscard]] MxResult<Rva> offset_to_rva(FileOffset offset) const;

    // ====================================================================
    // Чтение/запись байтов по RVA
    // ====================================================================

    /**
     * @brief Читает блок байтов из сырых данных файла по RVA.
     * @param rva Стартовый RVA.
     * @param size Количество байтов для чтения.
     * @return Представление (ByteView) запрошенного диапазона или ошибка.
     */
    [[nodiscard]] MxResult<ByteView> read_bytes(Rva rva, size_t size) const;

    /**
     * @brief Записывает блок байтов в сырые данные файла по RVA.
     * @param rva Стартовый RVA.
     * @param data Данные для записи.
     * @return MxStatus — успех или ошибка при выходе за границы.
     */
    [[nodiscard]] MxStatus write_bytes(Rva rva, ByteView data);

    // ====================================================================
    // Сырые данные
    // ====================================================================

    /**
     * @brief Возвращает неизменяемое представление сырых данных файла.
     * @return ByteView на raw_data_.
     */
    [[nodiscard]] ByteView raw_data() const noexcept {
        return ByteView{raw_data_.data(), raw_data_.size()};
    }

    /**
     * @brief Возвращает изменяемую ссылку на владеющий буфер сырых данных.
     * @return Ссылка на ByteBuffer.
     */
    [[nodiscard]] ByteBuffer& raw_data_buffer() noexcept { return raw_data_; }

    /**
     * @brief Возвращает константную ссылку на владеющий буфер сырых данных.
     * @return Константная ссылка на ByteBuffer.
     */
    [[nodiscard]] const ByteBuffer& raw_data_buffer() const noexcept { return raw_data_; }

    // ====================================================================
    // Сеттеры (используются PeParser при построении PeImage)
    // ====================================================================

    /// @brief Устанавливает сырые данные файла.
    /// @param data Владеющий буфер байтов.
    void set_raw_data(ByteBuffer data) { raw_data_ = std::move(data); }

    /// @brief Устанавливает архитектуру.
    /// @param arch Архитектура (x86/x64).
    void set_architecture(Architecture arch) noexcept { arch_ = arch; }

    /// @brief Устанавливает тип PE-файла.
    /// @param type Тип (executable/dynamic_library/kernel_driver).
    void set_pe_type(PeType type) noexcept { type_ = type; }

    /// @brief Устанавливает DOS-заголовок.
    /// @param hdr Копия DOS-заголовка.
    void set_dos_header(const pe::IMAGE_DOS_HEADER& hdr) noexcept { dos_header_ = hdr; }

    /// @brief Устанавливает NT-заголовки.
    /// @param hdrs Variant с NT-заголовками PE32 или PE32+.
    void set_nt_headers(NtHeaders hdrs) { nt_headers_ = std::move(hdrs); }

    /// @brief Устанавливает список секций.
    /// @param secs Вектор информации о секциях.
    void set_sections(std::vector<pe::SectionInfo> secs) { sections_ = std::move(secs); }

    /// @brief Устанавливает таблицу импортов.
    /// @param imps Вектор записей импорта.
    void set_imports(std::vector<pe::ImportEntry> imps) { imports_ = std::move(imps); }

    /// @brief Устанавливает таблицу экспортов.
    /// @param exp Таблица экспортов.
    void set_exports(pe::ExportTable exp) { exports_ = std::move(exp); }

    /// @brief Устанавливает таблицу релокаций.
    /// @param relocs Вектор блоков релокаций.
    void set_relocations(std::vector<pe::RelocationBlock> relocs) { relocations_ = std::move(relocs); }

    /// @brief Устанавливает RVA точки входа.
    /// @param rva RVA entry point.
    void set_entry_point_rva(Rva rva) noexcept { entry_point_rva_ = rva; }

    /// @brief Устанавливает базу загрузки образа.
    /// @param base Виртуальный адрес базы.
    void set_image_base(Va base) noexcept { image_base_ = base; }

    /// @brief Устанавливает файловое выравнивание.
    /// @param align Выравнивание в байтах.
    void set_file_alignment(uint32_t align) noexcept { file_alignment_ = align; }

    /// @brief Устанавливает выравнивание секций в памяти.
    /// @param align Выравнивание в байтах.
    void set_section_alignment(uint32_t align) noexcept { section_alignment_ = align; }

private:
    ByteBuffer                        raw_data_;                            ///< Оригинальные сырые данные файла

    Architecture                      arch_             = Architecture::x64;///< Архитектура
    PeType                            type_             = PeType::executable;///< Тип PE

    pe::IMAGE_DOS_HEADER              dos_header_{};                        ///< DOS-заголовок
    NtHeaders                         nt_headers_;                          ///< NT-заголовки (PE32/PE32+)

    std::vector<pe::SectionInfo>      sections_;                            ///< Секции PE
    std::vector<pe::ImportEntry>      imports_;                             ///< Таблица импортов
    pe::ExportTable                   exports_;                             ///< Таблица экспортов
    std::vector<pe::RelocationBlock>  relocations_;                         ///< Таблица релокаций

    Rva                               entry_point_rva_  = 0;               ///< RVA точки входа
    Va                                image_base_       = 0;               ///< Предпочтительная база загрузки
    uint32_t                          file_alignment_   = 0x200;           ///< Файловое выравнивание
    uint32_t                          section_alignment_= 0x1000;          ///< Выравнивание секций в памяти
};

// ============================================================================
// Инлайн-реализации методов PeImage
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

inline MxResult<FileOffset> PeImage::rva_to_offset(Rva rva) const {
    if (rva == 0) {
        return static_cast<FileOffset>(0);
    }

    if (!sections_.empty() && rva < sections_.front().virtual_address) {
        if (static_cast<size_t>(rva) < raw_data_.size()) {
            return static_cast<FileOffset>(rva);
        }
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "RVA 0x{:08X} в области заголовков выходит за пределы файла (размер: 0x{:X})",
            rva, raw_data_.size()));
    }

    const auto* sec = section_by_rva(rva);
    if (!sec) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "RVA 0x{:08X} не принадлежит ни одной секции", rva));
    }

    const uint32_t offset_in_section = rva - sec->virtual_address;
    if (offset_in_section >= sec->raw_size) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "RVA 0x{:08X} выходит за пределы сырых данных секции '{}' "
            "(смещение в секции: 0x{:X}, raw_size: 0x{:X})",
            rva, sec->name, offset_in_section, sec->raw_size));
    }

    return static_cast<FileOffset>(sec->raw_offset + offset_in_section);
}

inline MxResult<Rva> PeImage::offset_to_rva(FileOffset offset) const {
    if (offset == 0) {
        return static_cast<Rva>(0);
    }

    if (!sections_.empty() && offset < sections_.front().raw_offset) {
        return static_cast<Rva>(offset);
    }

    for (const auto& sec : sections_) {
        if (offset >= sec.raw_offset && offset < sec.raw_offset + sec.raw_size) {
            const uint32_t delta = offset - sec.raw_offset;
            return static_cast<Rva>(sec.virtual_address + delta);
        }
    }

    return std::unexpected(error::pe_fmt(
        PeErrorCode::invalid_rva,
        "Файловое смещение 0x{:08X} не принадлежит ни одной секции", offset));
}

inline MxResult<ByteView> PeImage::read_bytes(Rva rva, size_t size) const {
    auto offset_result = rva_to_offset(rva);
    if (!offset_result) {
        return std::unexpected(offset_result.error());
    }

    const FileOffset off = *offset_result;
    if (static_cast<size_t>(off) + size > raw_data_.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "Чтение по RVA 0x{:08X} (смещение 0x{:08X}, размер 0x{:X}) "
            "выходит за пределы файла (размер файла: 0x{:X})",
            rva, off, size, raw_data_.size()));
    }

    return ByteView{raw_data_.data() + off, size};
}

inline MxStatus PeImage::write_bytes(Rva rva, ByteView data) {
    auto offset_result = rva_to_offset(rva);
    if (!offset_result) {
        return std::unexpected(offset_result.error());
    }

    const FileOffset off = *offset_result;
    if (static_cast<size_t>(off) + data.size() > raw_data_.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "Запись по RVA 0x{:08X} (смещение 0x{:08X}, размер 0x{:X}) "
            "выходит за пределы файла (размер файла: 0x{:X})",
            rva, off, data.size(), raw_data_.size()));
    }

    std::ranges::copy(data, raw_data_.begin() + off);
    return {};
}

inline MxResult<uint32_t> PeImage::add_section(pe::SectionInfo section) {
    constexpr uint32_t max_sections = 96;
    if (sections_.size() >= max_sections) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Превышено максимальное количество секций ({}/{})",
            sections_.size(), max_sections));
    }

    if (!sections_.empty()) {
        const auto& last = sections_.back();
        const auto next_va = static_cast<uint32_t>(
            align_up(last.virtual_address + last.virtual_size, section_alignment_));
        section.virtual_address = next_va;

        const auto next_raw = static_cast<uint32_t>(
            align_up(last.raw_offset + last.raw_size, file_alignment_));
        section.raw_offset = next_raw;
    } else {
        section.virtual_address = static_cast<uint32_t>(
            align_up(sizeof(pe::IMAGE_DOS_HEADER) + 256, section_alignment_));
        section.raw_offset = static_cast<uint32_t>(
            align_up(sizeof(pe::IMAGE_DOS_HEADER) + 256, file_alignment_));
    }

    section.raw_size = static_cast<uint32_t>(
        align_up(section.data.size(), file_alignment_));
    if (section.virtual_size == 0) {
        section.virtual_size = static_cast<uint32_t>(section.data.size());
    }

    const auto index = static_cast<uint32_t>(sections_.size());
    sections_.push_back(std::move(section));

    std::visit([this](auto& nt) {
        nt.FileHeader.NumberOfSections = static_cast<uint16_t>(sections_.size());
    }, nt_headers_);

    return index;
}

} // namespace mx
