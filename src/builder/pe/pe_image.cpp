/**
 * @file pe_image.cpp
 * @brief Out-of-line `PeImage` methods that don't need to be inline.
 *
 * @details Splits the heavy methods (`rva_to_offset`, `offset_to_rva`,
 *          `read_bytes`, `write_bytes`, `add_section`) out of
 *          `pe_image.hpp` so the header stays small. The trivial
 *          accessors (`section_by_rva`, `section_by_name`,
 *          getter/setters) remain inline in the header.
 */

#include "mxprotector/pe/pe_image.hpp"

#include <algorithm>
#include <ranges>

namespace mx {

MxResult<FileOffset> PeImage::rva_to_offset(Rva rva) const {
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

MxResult<Rva> PeImage::offset_to_rva(FileOffset offset) const {
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

MxResult<ByteView> PeImage::read_bytes(Rva rva, size_t size) const {
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

MxStatus PeImage::write_bytes(Rva rva, ByteView data) {
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

MxResult<uint32_t> PeImage::add_section(pe::SectionInfo section) {
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
