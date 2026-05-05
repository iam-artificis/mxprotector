/**
 * @file chaos_reference_collector.cpp
 * @brief Implementation of `scan_all_references` — see header.
 */

#include "mxprotector/pe/layout/chaos_reference_collector.hpp"

#include <algorithm>
#include <cstddef>
#include <span>

#include "mxprotector/pe/refmap/code_reference_scanner.hpp"
#include "mxprotector/pe/refmap/delay_import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/export_directory_scanner.hpp"
#include "mxprotector/pe/refmap/import_descriptor_scanner.hpp"
#include "mxprotector/pe/refmap/load_config_directory_scanner.hpp"
#include "mxprotector/pe/refmap/obfuscated_jt_scanner.hpp"
#include "mxprotector/pe/refmap/reloc_absolute_va_scanner.hpp"
#include "mxprotector/pe/refmap/resource_directory_scanner.hpp"
#include "mxprotector/pe/refmap/structure_reference_scanner.hpp"
#include "mxprotector/pe/refmap/switch_jump_table_scanner.hpp"
#include "mxprotector/pe/refmap/tls_directory_scanner.hpp"
#include "mxprotector/pe/refmap/unwind_info_reference_scanner.hpp"
#include "mxprotector/pe/refmap/vm_call_pop_trampoline_scanner.hpp"

namespace mx::pe::chaos {

refmap::ReferenceTable scan_all_references(const PeImage& image) {
    refmap::ReferenceTable table;
    table.reserve(8192);

    // 1. Code-side references: rel32 / rel8 branches + RIP-relative
    //    operands. Emit per-section, ignoring per-section decode-error
    //    counts (chaos is best-effort, not a verifier). Each section
    //    forwards its registered `data_regions` so the scanner skips
    //    VM bytecode / handler-table bytes — bypassing both bogus-ref
    //    emissions and Zydis desync cascades that would otherwise leak
    //    misaligned references into adjacent real code.
    refmap::CodeReferenceScanner code;
    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;
        [[maybe_unused]] const auto errors = code.scan(
            ByteView{sec.data.data(),
                     std::min(sec.data.size(),
                              static_cast<std::size_t>(sec.virtual_size))},
            sec.virtual_address,
            std::span<const DataRegion>{
                sec.data_regions.data(), sec.data_regions.size()},
            table);
    }

    // 2. Top-level PE structure: entry point, DataDirectory pointers,
    //    .pdata RUNTIME_FUNCTION entries.
    refmap::StructureReferenceScanner{}.scan(image, table);

    // 3. Deep-directory scanners — IMPORT / EXPORT / DELAY_IMPORT /
    //    TLS / LOAD_CONFIG / RESOURCE.
    refmap::ImportDescriptorScanner{}.scan(image, table);
    refmap::ExportDirectoryScanner{}.scan(image, table);
    refmap::DelayImportDescriptorScanner{}.scan(image, table);
    refmap::TlsDirectoryScanner{}.scan(image, table);
    refmap::LoadConfigDirectoryScanner{}.scan(image, table);
    refmap::ResourceDirectoryScanner{}.scan(image, table);

    // 4. UNWIND_INFO trailers — `ExceptionHandler` and `ChainInfo`
    //    are 4-byte RVAs into code that the loader reads but `.reloc`
    //    does not cover. Without this scanner, post-shuffle binaries
    //    keep stale handler RVAs and crash the moment SEH dispatches.
    refmap::UnwindInfoReferenceScanner{}.scan(image, table);

    // 5. MSVC x64 switch jump tables — the
    //    `mov r32, [imageBase + idx*4 + JT_RVA] / add / jmp r64`
    //    dispatcher reads 4-byte RVAs from `.rdata` that, like
    //    UNWIND_INFO trailers, are image-relative and hence not in
    //    `.reloc`.
    refmap::SwitchJumpTableScanner{}.scan(image, table);

    // 5a. Obfuscated tail-dispatch jump tables — the VM tail dispatch
    //     emits a 7-instruction dispatcher whose JT entries are
    //     `(target_rva - jt_base_rva) XOR KEY`. The scanner extracts
    //     KEY and emits one `xor_encoded_signed_delta_imm32` reference
    //     per entry so the patcher can re-encrypt the entry after
    //     chaos relocates the target.
    refmap::ObfuscatedJtScanner{}.scan(image, table);

    // 6. MxProtector VM `CallPop` trampolines —
    //    `call $+5; add qword [rsp], imm32; ret` whose imm32 is a
    //    rel32 anchored at `slot - 4` (call_after_rva). Zydis sees
    //    the imm32 as a non-relative immediate so
    //    `CodeReferenceScanner` does not produce a slot for it.
    refmap::VmCallPopTrampolineScanner{}.scan(image, table);

    // 7. Final pass — every IMAGE_REL_BASED_DIR64 entry the linker
    //    emitted. Catches any absolute-VA slot the targeted scanners
    //    missed (defence in depth).
    refmap::RelocAbsoluteVaScanner{}.scan(image, table);

    // 8. Pre-scanned-ref slot overrides (B.4.22). Passes that emit
    //    non-balanced indirect-call stubs register a `PreScannedRefSlot`
    //    per stub on the stub section. We append one
    //    `rel32_with_imm_offset` reference per entry. The patcher
    //    iterates references in append order, so these LAND AFTER any
    //    duplicate `rel`-encoded reference the `CodeReferenceScanner`
    //    produced for the same slot — the final disp32 byte value is
    //    the unbalanced one.
    for (const auto& sec : image.sections()) {
        for (const auto& s : sec.pre_scanned_refs) {
            table.add(refmap::Reference{
                .location_rva = s.slot_rva,
                .target_rva   = s.target_rva,
                .width        = refmap::ReferenceWidth::byte4,
                .encoding     = refmap::ReferenceEncoding::rel32_with_imm_offset,
                .origin       = refmap::ReferenceOrigin::indirect_call_stub_lea,
                .aux          = static_cast<std::uint64_t>(
                    static_cast<std::uint32_t>(s.imm_offset)),
            });
        }
    }

    // 9. Extra RVA refs (B.4.23.1). `PdataChainEmitter` registers
    //    these for each ChainInfo RVA inside the new `.mxchain`
    //    section so the chaos refmap remaps them through the chunk
    //    planner — `rva` for `BeginAddress` / `UnwindInfoAddress`,
    //    `rva_end_exclusive` for `EndAddress`.
    for (const auto& sec : image.sections()) {
        for (const auto& s : sec.extra_rva_refs) {
            table.add(refmap::Reference{
                .location_rva = s.slot_rva,
                .target_rva   = s.target_rva,
                .width        = refmap::ReferenceWidth::byte4,
                .encoding     = s.end_exclusive
                    ? refmap::ReferenceEncoding::rva_end_exclusive
                    : refmap::ReferenceEncoding::rva,
                .origin       = refmap::ReferenceOrigin::pdata_runtime_function,
            });
        }
    }

    return table;
}

} // namespace mx::pe::chaos
