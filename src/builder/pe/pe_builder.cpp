/**
 * @file pe_builder.cpp
 * @brief [BUILDER] Реализация PeBuilder — полная реконструкция PE-файла из PeImage.
 *
 * @details Собирает валидный PE-файл из высокоуровневого представления:
 *          1. DOS-заголовок и стаб (из оригинальных данных или минимальный)
 *          2. NT-заголовки (PE32/PE32+) с пересчитанными полями
 *          3. Таблица заголовков секций
 *          4. Данные секций с выравниванием по FileAlignment
 *
 *          Все размеры (SizeOfImage, SizeOfHeaders) пересчитываются на основе
 *          актуального состояния секций. Выравнивание гарантируется.
 *
 * @note generate_output_path создаёт имя вида "input.mx.exe" (суффикс .mx перед расширением).
 */

#include "mxprotector/pe/pe_builder.hpp"

#include <cstring>
#include <algorithm>

namespace mx {

// ============================================================================
// PeBuilder::build
// ============================================================================

MxResult<ByteBuffer> PeBuilder::build(const PeImage& image) {
    const auto& sections = image.sections();
    const uint32_t file_alignment = image.file_alignment();
    const uint32_t section_alignment = image.section_alignment();

    if (file_alignment == 0 || section_alignment == 0) {
        return std::unexpected(error::pe_fmt(
            PeErrorCode::section_alignment_violation,
            "Некорректное выравнивание: FileAlignment=0x{:X}, SectionAlignment=0x{:X}",
            file_alignment, section_alignment));
    }

    const uint32_t size_of_headers = calculate_size_of_headers(image);
    const uint32_t size_of_image = calculate_size_of_image(image);

    uint32_t file_size = size_of_headers;
    for (const auto& sec : sections) {
        const auto sec_end = static_cast<uint32_t>(
            align_up(sec.raw_offset + sec.raw_size, file_alignment));
        if (sec_end > file_size) {
            file_size = sec_end;
        }
    }

    ByteBuffer output(file_size, 0);

    write_dos_header(output, image);
    write_nt_headers(output, image);

    uint32_t section_header_offset = 0;
    std::visit([&](const auto& nt) {
        const auto lfanew = static_cast<uint32_t>(image.dos_header().e_lfanew);
        using NtType = std::decay_t<decltype(nt)>;
        section_header_offset = static_cast<uint32_t>(
            lfanew + offsetof(NtType, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader);
    }, image.nt_headers());

    write_section_headers(output, image, section_header_offset);

    std::visit([&](auto nt) {
        nt.OptionalHeader.SizeOfHeaders = size_of_headers;
        nt.OptionalHeader.SizeOfImage = size_of_image;

        const auto lfanew = static_cast<uint32_t>(image.dos_header().e_lfanew);
        if (lfanew + sizeof(nt) <= output.size()) {
            std::memcpy(output.data() + lfanew, &nt, sizeof(nt));
        }
    }, image.nt_headers());

    write_section_data(output, image);

    return output;
}

// ============================================================================
// PeBuilder::generate_output_path
// ============================================================================

std::filesystem::path PeBuilder::generate_output_path(
    const std::filesystem::path& input_path)
{
    auto stem = input_path.stem();
    auto ext = input_path.extension();
    auto parent = input_path.parent_path();

    auto new_name = stem.string() + ".mx" + ext.string();
    return parent / new_name;
}

// ============================================================================
// PeBuilder::write_dos_header
// ============================================================================

void PeBuilder::write_dos_header(ByteBuffer& output, const PeImage& image) {
    const auto& raw = image.raw_data_buffer();
    const auto lfanew = static_cast<size_t>(image.dos_header().e_lfanew);

    const size_t dos_region_size = std::min(lfanew, raw.size());
    if (dos_region_size > 0 && dos_region_size <= output.size()) {
        std::memcpy(output.data(), raw.data(), dos_region_size);
    }

    if (dos_region_size < sizeof(pe::IMAGE_DOS_HEADER) &&
        sizeof(pe::IMAGE_DOS_HEADER) <= output.size())
    {
        pe::IMAGE_DOS_HEADER dos = image.dos_header();
        std::memcpy(output.data(), &dos, sizeof(pe::IMAGE_DOS_HEADER));
    }
}

// ============================================================================
// PeBuilder::write_nt_headers
// ============================================================================

void PeBuilder::write_nt_headers(ByteBuffer& output, const PeImage& image) {
    const auto lfanew = static_cast<size_t>(image.dos_header().e_lfanew);

    std::visit([&](const auto& nt) {
        if (lfanew + sizeof(nt) <= output.size()) {
            std::memcpy(output.data() + lfanew, &nt, sizeof(nt));
        }
    }, image.nt_headers());
}

// ============================================================================
// PeBuilder::write_section_headers
// ============================================================================

void PeBuilder::write_section_headers(
    ByteBuffer& output,
    const PeImage& image,
    uint32_t section_header_offset)
{
    const auto& sections = image.sections();

    for (size_t i = 0; i < sections.size(); ++i) {
        const auto& sec = sections[i];
        const size_t hdr_offset = section_header_offset +
            i * sizeof(pe::IMAGE_SECTION_HEADER);

        if (hdr_offset + sizeof(pe::IMAGE_SECTION_HEADER) > output.size()) break;

        pe::IMAGE_SECTION_HEADER hdr{};

        const size_t name_len = std::min(sec.name.size(), static_cast<size_t>(pe::IMAGE_SIZEOF_SHORT_NAME));
        std::memcpy(hdr.Name, sec.name.c_str(), name_len);

        hdr.Misc.VirtualSize = sec.virtual_size;
        hdr.VirtualAddress = sec.virtual_address;
        hdr.SizeOfRawData = sec.raw_size;
        hdr.PointerToRawData = sec.raw_offset;
        hdr.Characteristics = sec.characteristics;

        std::memcpy(output.data() + hdr_offset, &hdr, sizeof(pe::IMAGE_SECTION_HEADER));
    }
}

// ============================================================================
// PeBuilder::write_section_data
// ============================================================================

void PeBuilder::write_section_data(ByteBuffer& output, const PeImage& image) {
    for (const auto& sec : image.sections()) {
        if (sec.data.empty() || sec.raw_offset == 0) continue;

        const size_t dest_offset = sec.raw_offset;
        const size_t copy_size = std::min(sec.data.size(),
            static_cast<size_t>(sec.raw_size));

        if (dest_offset + copy_size > output.size()) {
            output.resize(dest_offset + copy_size, 0);
        }

        std::memcpy(output.data() + dest_offset, sec.data.data(), copy_size);
    }
}

// ============================================================================
// PeBuilder::calculate_size_of_image
// ============================================================================

uint32_t PeBuilder::calculate_size_of_image(const PeImage& image) {
    const auto& sections = image.sections();
    const uint32_t sa = image.section_alignment();

    if (sections.empty()) {
        return static_cast<uint32_t>(align_up(
            sizeof(pe::IMAGE_DOS_HEADER) + 256, sa));
    }

    uint32_t max_end = 0;
    for (const auto& sec : sections) {
        const auto sec_end = static_cast<uint32_t>(
            align_up(sec.virtual_address + std::max(sec.virtual_size, sec.raw_size), sa));
        if (sec_end > max_end) max_end = sec_end;
    }

    return max_end;
}

// ============================================================================
// PeBuilder::calculate_size_of_headers
// ============================================================================

uint32_t PeBuilder::calculate_size_of_headers(const PeImage& image) {
    const uint32_t fa = image.file_alignment();

    uint32_t headers_raw = 0;
    std::visit([&](const auto& nt) {
        const auto lfanew = static_cast<uint32_t>(image.dos_header().e_lfanew);
        using NtType = std::decay_t<decltype(nt)>;
        headers_raw = static_cast<uint32_t>(
            lfanew + offsetof(NtType, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader
            + static_cast<uint32_t>(image.sections().size()) * sizeof(pe::IMAGE_SECTION_HEADER));
    }, image.nt_headers());

    return static_cast<uint32_t>(align_up(headers_raw, fa));
}

} // namespace mx
