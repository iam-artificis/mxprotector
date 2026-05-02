/**
 * @file pe_parser.cpp
 * @brief [BUILDER] Реализация PeParser — полный разбор PE-файла с валидацией.
 *
 * @details Выполняет последовательный разбор всех компонентов PE:
 *          DOS-заголовок → NT-заголовки → секции → импорты → экспорты → релокации.
 *          Каждый шаг строго валидирует границы — ни одно чтение не выходит
 *          за пределы входного буфера. Ошибки возвращаются через MxResult
 *          с подробными русскоязычными описаниями.
 *
 * @note Парсер не модифицирует входные данные. Создаёт независимую копию raw_data
 *       внутри PeImage. Использует статические методы ImportTableManager,
 *       ExportTableManager, RelocationTableManager для разбора таблиц.
 */

#include "mxprotector/pe/pe_parser.hpp"
#include "mxprotector/pe/import_table.hpp"
#include "mxprotector/pe/export_table.hpp"
#include "mxprotector/pe/relocation_table.hpp"

#include <cstring>
#include <algorithm>

namespace mx {

namespace {

/**
 * @brief Безопасно читает структуру T из буфера по указанному смещению.
 * @tparam T Тип читаемой структуры (POD).
 * @param data Буфер данных.
 * @param offset Смещение от начала буфера.
 * @return Копия структуры или ошибка при выходе за границы.
 */
template <typename T>
[[nodiscard]] MxResult<T> safe_read(ByteView data, size_t offset) {
    if (offset + sizeof(T) > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::file_too_small,
            "Невозможно прочитать структуру размером {} байт по смещению 0x{:X} "
            "(размер файла: 0x{:X})",
            sizeof(T), offset, data.size()));
    }
    T result{};
    std::memcpy(&result, data.data() + offset, sizeof(T));
    return result;
}

} // anonymous namespace

// ============================================================================
// PeParser::parse
// ============================================================================

MxResult<PeImage> PeParser::parse(ByteView raw_data) {
    constexpr size_t min_pe_size = sizeof(pe::IMAGE_DOS_HEADER);
    if (raw_data.size() < min_pe_size) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::file_too_small,
            "Файл слишком мал для PE: {} байт (минимум {})",
            raw_data.size(), min_pe_size));
    }

    auto dos_result = parse_dos_header(raw_data);
    if (!dos_result) {
        return std::unexpected(dos_result.error());
    }
    const auto& dos = *dos_result;

    const auto lfanew = static_cast<uint32_t>(dos.e_lfanew);
    if (lfanew + sizeof(uint32_t) > raw_data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::lfanew_out_of_bounds,
            "e_lfanew (0x{:X}) указывает за пределы файла (размер: 0x{:X})",
            lfanew, raw_data.size()));
    }

    auto nt_sig_result = safe_read<uint32_t>(raw_data, lfanew);
    if (!nt_sig_result) return std::unexpected(nt_sig_result.error());

    if (*nt_sig_result != pe::IMAGE_NT_SIGNATURE) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_nt_signature,
            "Неверная сигнатура NT-заголовков: 0x{:08X} (ожидалось 0x{:08X})",
            *nt_sig_result, pe::IMAGE_NT_SIGNATURE));
    }

    const size_t file_header_offset = lfanew + sizeof(uint32_t);
    auto file_hdr_result = safe_read<pe::IMAGE_FILE_HEADER>(raw_data, file_header_offset);
    if (!file_hdr_result) return std::unexpected(file_hdr_result.error());
    const auto& file_header = *file_hdr_result;

    auto arch_result = detect_architecture(file_header.Machine);
    if (!arch_result) return std::unexpected(arch_result.error());
    const Architecture arch = *arch_result;

    const size_t optional_header_offset = file_header_offset + sizeof(pe::IMAGE_FILE_HEADER);
    if (optional_header_offset + sizeof(uint16_t) > raw_data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_optional_header,
            "Невозможно прочитать Magic Optional Header по смещению 0x{:X}",
            optional_header_offset));
    }

    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, raw_data.data() + optional_header_offset, sizeof(uint16_t));

    PeImage image;
    image.set_dos_header(dos);
    image.set_architecture(arch);

    uint32_t section_header_offset = 0;
    uint16_t subsystem = 0;

    if (opt_magic == pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto nt_result = safe_read<pe::IMAGE_NT_HEADERS64>(raw_data, lfanew);
        if (!nt_result) return std::unexpected(nt_result.error());

        const auto& nt = *nt_result;
        image.set_nt_headers(nt);
        image.set_entry_point_rva(nt.OptionalHeader.AddressOfEntryPoint);
        image.set_image_base(nt.OptionalHeader.ImageBase);
        image.set_file_alignment(nt.OptionalHeader.FileAlignment);
        image.set_section_alignment(nt.OptionalHeader.SectionAlignment);
        subsystem = nt.OptionalHeader.Subsystem;

        section_header_offset = static_cast<uint32_t>(
            lfanew + offsetof(pe::IMAGE_NT_HEADERS64, OptionalHeader)
            + file_header.SizeOfOptionalHeader);
    }
    else if (opt_magic == pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto nt_result = safe_read<pe::IMAGE_NT_HEADERS32>(raw_data, lfanew);
        if (!nt_result) return std::unexpected(nt_result.error());

        const auto& nt = *nt_result;
        image.set_nt_headers(nt);
        image.set_entry_point_rva(nt.OptionalHeader.AddressOfEntryPoint);
        image.set_image_base(static_cast<Va>(nt.OptionalHeader.ImageBase));
        image.set_file_alignment(nt.OptionalHeader.FileAlignment);
        image.set_section_alignment(nt.OptionalHeader.SectionAlignment);
        subsystem = nt.OptionalHeader.Subsystem;

        section_header_offset = static_cast<uint32_t>(
            lfanew + offsetof(pe::IMAGE_NT_HEADERS32, OptionalHeader)
            + file_header.SizeOfOptionalHeader);
    }
    else {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_optional_header,
            "Неизвестный Magic Optional Header: 0x{:04X} "
            "(ожидалось 0x{:04X} для PE32 или 0x{:04X} для PE32+)",
            opt_magic, pe::IMAGE_NT_OPTIONAL_HDR32_MAGIC, pe::IMAGE_NT_OPTIONAL_HDR64_MAGIC));
    }

    image.set_pe_type(detect_pe_type(file_header.Characteristics, subsystem));

    auto sections_result = parse_sections(raw_data, section_header_offset,
                                          file_header.NumberOfSections);
    if (!sections_result) return std::unexpected(sections_result.error());
    image.set_sections(std::move(*sections_result));

    auto rva_converter = make_rva_converter(image.sections(), raw_data.size());

    auto get_data_dir = [&](uint32_t index) -> std::pair<Rva, uint32_t> {
        return std::visit([index](const auto& nt) -> std::pair<Rva, uint32_t> {
            if (index < nt.OptionalHeader.NumberOfRvaAndSizes) {
                return {nt.OptionalHeader.DataDirectory[index].VirtualAddress,
                        nt.OptionalHeader.DataDirectory[index].Size};
            }
            return {0, 0};
        }, image.nt_headers());
    };

    auto [import_rva, import_size] = get_data_dir(pe::IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (import_rva != 0 && import_size != 0) {
        auto imports_result = ImportTableManager::parse_imports(
            raw_data, import_rva, import_size, arch == Architecture::x64, rva_converter);
        if (imports_result) {
            image.set_imports(std::move(*imports_result));
        }
    }

    auto [export_rva, export_size] = get_data_dir(pe::IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (export_rva != 0 && export_size != 0) {
        auto exports_result = ExportTableManager::parse_exports(
            raw_data, export_rva, export_size, rva_converter);
        if (exports_result) {
            image.set_exports(std::move(*exports_result));
        }
    }

    auto [reloc_rva, reloc_size] = get_data_dir(pe::IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (reloc_rva != 0 && reloc_size != 0) {
        auto relocs_result = RelocationTableManager::parse_relocations(
            raw_data, reloc_rva, reloc_size, rva_converter);
        if (relocs_result) {
            image.set_relocations(std::move(*relocs_result));
        }
    }

    image.set_raw_data(ByteBuffer(raw_data.begin(), raw_data.end()));

    return image;
}

// ============================================================================
// PeParser::parse_dos_header
// ============================================================================

MxResult<pe::IMAGE_DOS_HEADER> PeParser::parse_dos_header(ByteView data) {
    auto dos = safe_read<pe::IMAGE_DOS_HEADER>(data, 0);
    if (!dos) return std::unexpected(dos.error());

    if (dos->e_magic != pe::IMAGE_DOS_SIGNATURE) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_dos_signature,
            "Неверная сигнатура DOS: 0x{:04X} (ожидалось 0x{:04X} \"MZ\")",
            dos->e_magic, pe::IMAGE_DOS_SIGNATURE));
    }

    if (dos->e_lfanew < 0) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::lfanew_out_of_bounds,
            "e_lfanew отрицательно: {} — повреждённый PE",
            dos->e_lfanew));
    }

    if (static_cast<size_t>(dos->e_lfanew) >= data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::lfanew_out_of_bounds,
            "e_lfanew (0x{:X}) >= размер файла (0x{:X})",
            dos->e_lfanew, data.size()));
    }

    return *dos;
}

// ============================================================================
// PeParser::detect_architecture
// ============================================================================

MxResult<Architecture> PeParser::detect_architecture(uint16_t machine) {
    switch (machine) {
        case pe::IMAGE_FILE_MACHINE_I386:
            return Architecture::x86;
        case pe::IMAGE_FILE_MACHINE_AMD64:
            return Architecture::x64;
        default:
            return std::unexpected(error::pe_fmt(
                PeErrorCode::unsupported_architecture,
                "Неподдерживаемый тип машины: 0x{:04X} (поддерживаются x86=0x{:04X}, x64=0x{:04X})",
                machine, pe::IMAGE_FILE_MACHINE_I386, pe::IMAGE_FILE_MACHINE_AMD64));
    }
}

// ============================================================================
// PeParser::detect_pe_type
// ============================================================================

PeType PeParser::detect_pe_type(uint16_t characteristics, uint16_t subsystem) {
    // Subsystem-driven kinds outrank the DLL bit because UEFI runtime
    // drivers and EFI ROMs carry their own subsystem id but the DLL
    // characteristics bit is also commonly set on them — without this
    // ordering they would silently parse as `dynamic_library` and
    // engage user-mode passes that have no business running there.
    if (pe::is_efi_subsystem(subsystem)) {
        return PeType::efi_application;
    }
    if (subsystem == pe::IMAGE_SUBSYSTEM_NATIVE) {
        return PeType::kernel_driver;
    }
    if (characteristics & pe::IMAGE_FILE_DLL) {
        return PeType::dynamic_library;
    }
    return PeType::executable;
}

// ============================================================================
// PeParser::parse_sections
// ============================================================================

MxResult<std::vector<pe::SectionInfo>> PeParser::parse_sections(
    ByteView data,
    uint32_t section_header_offset,
    uint16_t num_sections)
{
    constexpr uint16_t max_sections = 96;
    if (num_sections > max_sections) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Слишком много секций: {} (максимум {})",
            num_sections, max_sections));
    }

    const size_t required_size = static_cast<size_t>(section_header_offset) +
        static_cast<size_t>(num_sections) * sizeof(pe::IMAGE_SECTION_HEADER);
    if (required_size > data.size()) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_out_of_bounds,
            "Таблица секций (смещение 0x{:X}, {} записей × {} байт = 0x{:X}) "
            "выходит за пределы файла (0x{:X})",
            section_header_offset, num_sections, sizeof(pe::IMAGE_SECTION_HEADER),
            required_size, data.size()));
    }

    std::vector<pe::SectionInfo> sections;
    sections.reserve(num_sections);

    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t hdr_offset = section_header_offset +
            static_cast<size_t>(i) * sizeof(pe::IMAGE_SECTION_HEADER);

        auto hdr_result = safe_read<pe::IMAGE_SECTION_HEADER>(data, hdr_offset);
        if (!hdr_result) return std::unexpected(hdr_result.error());
        const auto& hdr = *hdr_result;

        pe::SectionInfo sec;

        char name_buf[pe::IMAGE_SIZEOF_SHORT_NAME + 1] = {};
        std::memcpy(name_buf, hdr.Name, pe::IMAGE_SIZEOF_SHORT_NAME);
        sec.name = std::string(name_buf);

        sec.virtual_size    = hdr.Misc.VirtualSize;
        sec.virtual_address = hdr.VirtualAddress;
        sec.raw_size        = hdr.SizeOfRawData;
        sec.raw_offset      = hdr.PointerToRawData;
        sec.characteristics = hdr.Characteristics;

        if (hdr.PointerToRawData != 0 && hdr.SizeOfRawData != 0) {
            if (static_cast<size_t>(hdr.PointerToRawData) + hdr.SizeOfRawData > data.size()) {
                return std::unexpected(error::pe_fmt(
                    PeErrorCode::section_out_of_bounds,
                    "Секция '{}' [{}]: данные (смещение 0x{:X}, размер 0x{:X}) "
                    "выходят за пределы файла (0x{:X})",
                    sec.name, i, hdr.PointerToRawData, hdr.SizeOfRawData, data.size()));
            }

            const auto* begin = data.data() + hdr.PointerToRawData;
            sec.data.assign(begin, begin + hdr.SizeOfRawData);
        }
        else {
            sec.data.clear();
        }

        sections.push_back(std::move(sec));
    }

    return sections;
}

// ============================================================================
// PeParser::make_rva_converter
// ============================================================================

std::function<MxResult<FileOffset>(Rva)> PeParser::make_rva_converter(
    const std::vector<pe::SectionInfo>& sections,
    size_t data_size)
{
    return [&sections, data_size](Rva rva) -> MxResult<FileOffset> {
        if (rva == 0) return static_cast<FileOffset>(0);

        if (!sections.empty() && rva < sections.front().virtual_address) {
            if (static_cast<size_t>(rva) < data_size) {
                return static_cast<FileOffset>(rva);
            }
            return std::unexpected(error::pe_fmt(
                PeErrorCode::invalid_rva,
                "RVA 0x{:08X} в области заголовков за пределами файла (0x{:X})",
                rva, data_size));
        }

        for (const auto& sec : sections) {
            if (sec.contains_rva(rva)) {
                const uint32_t delta = rva - sec.virtual_address;
                if (delta < sec.raw_size) {
                    return static_cast<FileOffset>(sec.raw_offset + delta);
                }
                return std::unexpected(error::pe_fmt(
                    PeErrorCode::invalid_rva,
                    "RVA 0x{:08X} в секции '{}' за пределами сырых данных "
                    "(смещение в секции: 0x{:X}, raw_size: 0x{:X})",
                    rva, sec.name, delta, sec.raw_size));
            }
        }

        return std::unexpected(error::pe_fmt(
            PeErrorCode::invalid_rva,
            "RVA 0x{:08X} не принадлежит ни одной секции", rva));
    };
}

} // namespace mx
