/**
 * @file relocation_injector.cpp
 * @brief Implementation of `RelocationInjector` — see header.
 */

#include "mxprotector/pe/relocation_injector.hpp"

namespace mx::pe {

namespace {

/// 4 KB page alignment — every PE base-relocation block describes a
/// single 4 KB virtual page, so the page RVA is the target with the
/// low 12 bits cleared.
constexpr Rva kPageMask = 0xFFFFF000u;

} // anonymous namespace

RelocationBlock& RelocationInjector::block_for_page(Rva rva) {
    const Rva page = rva & kPageMask;
    auto& blocks = image_.relocations();
    for (auto& b : blocks) {
        if (b.page_rva == page) return b;
    }
    blocks.push_back(RelocationBlock{.page_rva = page, .entries = {}});
    return blocks.back();
}

void RelocationInjector::add(Rva target_rva, std::uint16_t type) {
    auto& block = block_for_page(target_rva);
    block.entries.push_back(RelocationEntry{
        .rva  = target_rva,
        .type = type,
    });
}

} // namespace mx::pe
