/**
 * @file packer_pass.cpp
 * @brief [BUILDER] PackerPass — self-unpacking PE protector implementation.
 *
 * Strategy:
 *   1. Strip base relocations (set IMAGE_FILE_RELOCS_STRIPPED, clear DYNAMIC_BASE,
 *      clear the IMAGE_DIRECTORY_ENTRY_BASERELOC directory). The loader will
 *      load at the preferred ImageBase without applying any fixups, so the
 *      encrypted bytes survive loader → stub unchanged.
 *   2. Generate a per-build random 256-byte XOR key.
 *   3. Encrypt .text in place: enc[i] = plain[i] ^ key[i % 256]. Mark .text
 *      writable so the stub can decrypt in place.
 *   4. Emit an x64 decryption stub into a new .mxpack section. The stub:
 *        - uses RIP-relative LEAs to locate .text and the embedded key,
 *        - masks the byte index against 0xFF so a single-byte counter drives
 *          the key stream,
 *        - jmps to the original entry point via rel32.
 *   5. Retarget the PE entry point to the stub.
 *
 * Limitations (MVP):
 *   - Only .text is encrypted.
 *   - .reloc is stripped — binaries must be loadable at ImageBase.
 *   - Stub does not restore the .text page protection after decrypting.
 */

#include "mxprotector/protection/packer/packer_pass.hpp"
#include "mxprotector/core/context.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/section_manager.hpp"
#include "mxprotector/pe/pe_image.hpp"
#include "mxprotector/pe/pe_types.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <format>
#include <variant>

namespace mx {

namespace {

/// 256-byte XOR key stream. The stub counts bytes with `inc dl` so the key
/// wraps automatically at 256.
constexpr uint32_t kKeySize = 256;

/// Size of the stub *code* (before the key). Fixed so we can patch rel32s
/// without measuring the buffer after the fact.
///   push rdi/rsi/rcx/rdx/rax          = 5 bytes
///   lea rdi, [rip + rel32]             = 7
///   lea rsi, [rip + rel32]             = 7
///   mov ecx, imm32                     = 5
///   xor edx, edx                       = 2
///   .loop:
///     mov al, [rdi]                    = 2
///     xor al, [rsi + rdx]              = 3
///     mov [rdi], al                    = 2
///     inc rdi                          = 3
///     inc dl                           = 2
///     dec rcx                          = 3
///     jnz .loop                        = 2
///   pop rax/rdx/rcx/rsi/rdi            = 5
///   jmp rel32                          = 5
///   -------------------------------------
///   total                              = 53
constexpr uint32_t kStubCodeSize = 53;

struct StubPatches {
    uint32_t rel_to_text_at;   ///< patch offset inside stub (rel32 from end-of-lea to .text)
    uint32_t rel_to_key_at;    ///< patch offset (rel32 from end-of-lea to embedded key)
    uint32_t rel_to_oep_at;    ///< patch offset (rel32 from end-of-jmp to OEP)
    uint32_t text_size_at;     ///< patch offset of the `mov ecx, imm32` immediate
};

/// Build the stub code bytes (without patching rel32s yet) and report where
/// the four placeholders need to be filled in.
[[nodiscard]] std::pair<ByteBuffer, StubPatches> build_stub_bytes() {
    ByteBuffer buf;
    buf.reserve(kStubCodeSize + kKeySize);

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

    // Save registers we trash during decryption.
    u8(0x57);  // push rdi
    u8(0x56);  // push rsi
    u8(0x51);  // push rcx
    u8(0x52);  // push rdx
    u8(0x50);  // push rax

    StubPatches patches{};

    // lea rdi, [rip + rel32]   ; rdi = &text[0]
    u8(0x48); u8(0x8D); u8(0x3D);
    patches.rel_to_text_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // lea rsi, [rip + rel32]   ; rsi = &key[0]
    u8(0x48); u8(0x8D); u8(0x35);
    patches.rel_to_key_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // mov ecx, imm32           ; text_size (zero-extends to rcx)
    u8(0xB9);
    patches.text_size_at = static_cast<uint32_t>(buf.size());
    u32(0);

    // xor edx, edx             ; rdx = 0 (key-stream index)
    u8(0x31); u8(0xD2);

    // .loop:
    // mov al, [rdi]             ; 8A 07
    u8(0x8A); u8(0x07);
    // xor al, [rsi + rdx*1]     ; 32 04 16   (ModRM+SIB; scale=0, index=rdx, base=rsi)
    u8(0x32); u8(0x04); u8(0x16);
    // mov [rdi], al             ; 88 07
    u8(0x88); u8(0x07);
    // inc rdi                   ; 48 FF C7
    u8(0x48); u8(0xFF); u8(0xC7);
    // inc dl                    ; FE C2  — wraps at 256 (exactly the key length)
    u8(0xFE); u8(0xC2);
    // dec rcx                   ; 48 FF C9
    u8(0x48); u8(0xFF); u8(0xC9);
    // jnz .loop                 ; 75 rel8 — target = start of `mov al, [rdi]`
    //
    // rel8 = target - (current + 2)
    // target is the `mov al, [rdi]` instruction. It starts at
    // (position of `xor edx, edx` end) = xor_edx_end_pos below.
    // We compute rel8 at emit time.
    const uint32_t loop_body_start = patches.text_size_at + 4 + 2;  // after `xor edx, edx`
    const uint32_t jnz_end         = static_cast<uint32_t>(buf.size()) + 2;
    const int32_t  rel8            = static_cast<int32_t>(loop_body_start) - static_cast<int32_t>(jnz_end);
    u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));

    // Restore registers.
    u8(0x58);  // pop rax
    u8(0x5A);  // pop rdx
    u8(0x59);  // pop rcx
    u8(0x5E);  // pop rsi
    u8(0x5F);  // pop rdi

    // jmp rel32   ; to OEP
    u8(0xE9);
    patches.rel_to_oep_at = static_cast<uint32_t>(buf.size());
    u32(0);

    return {std::move(buf), patches};
}

/// Write an int32 little-endian into a buffer at `offset`.
void write_i32(ByteBuffer& buf, uint32_t offset, int32_t value) {
    std::memcpy(buf.data() + offset, &value, sizeof(value));
}

/// Strip base relocations: clear the directory entry, set the file header's
/// IMAGE_FILE_RELOCS_STRIPPED bit, clear DYNAMIC_BASE in DllCharacteristics,
/// and blank out in-memory .reloc contents so PeBuilder doesn't re-emit them.
void disable_relocations(PeImage& image) {
    std::visit([&](auto& nt) {
        using NT = std::decay_t<decltype(nt)>;

        nt.FileHeader.Characteristics |= pe::IMAGE_FILE_RELOCS_STRIPPED;
        nt.OptionalHeader.DllCharacteristics &=
            static_cast<uint16_t>(~pe::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE);

        if constexpr (std::is_same_v<NT, pe::IMAGE_NT_HEADERS32> ||
                      std::is_same_v<NT, pe::IMAGE_NT_HEADERS64>) {
            if (pe::IMAGE_DIRECTORY_ENTRY_BASERELOC < nt.OptionalHeader.NumberOfRvaAndSizes) {
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
                nt.OptionalHeader.DataDirectory[pe::IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
            }
        }
    }, image.nt_headers());

    image.set_relocations({});

    for (auto& sec : image.sections()) {
        if (sec.name == ".reloc") {
            std::fill(sec.data.begin(), sec.data.end(), static_cast<uint8_t>(0));
        }
    }
}

/// Find the primary code section to encrypt. For MSVC-built PEs this is
/// ".text". If a CFF trampoline section (".mxprot1") was added earlier, it
/// is also encrypted so CFF code is not left in the clear.
std::vector<size_t> collect_target_sections(const PeImage& image) {
    std::vector<size_t> indices;
    for (size_t i = 0; i < image.sections().size(); ++i) {
        const auto& sec = image.sections()[i];
        if (sec.data.empty()) continue;
        if (sec.name == ".text" || sec.name == ".mxprot1" || sec.name == ".mxvm") {
            indices.push_back(i);
        }
    }
    return indices;
}

} // anonymous namespace

bool PackerPass::is_applicable(const ProtectionContext& ctx) const noexcept {
    return ctx.config().enable_packer;
}

MxStatus PackerPass::execute(ProtectionContext& ctx) {
    ctx.log("PackerPass: начало самораспаковывающейся защиты");

    auto target_indices = collect_target_sections(ctx.pe_image());
    if (target_indices.empty()) {
        ctx.log("PackerPass: нет подходящих секций, пропуск");
        return {};
    }

    // MVP supports a single encrypted section per build (the primary .text).
    // Additional sections can be wired in later by emitting a section-table
    // at the head of the stub.
    const size_t target_idx = target_indices.front();
    auto& target = ctx.pe_image().sections()[target_idx];

    ctx.log_fmt("PackerPass: шифруется '{}' (RVA=0x{:08X}, {} байт)",
        target.name, target.virtual_address,
        static_cast<uint32_t>(target.data.size()));

    // 1. Kill base relocations so the encrypted bytes survive to runtime.
    disable_relocations(ctx.pe_image());
    ctx.log("PackerPass: релокации отключены (IMAGE_FILE_RELOCS_STRIPPED)");

    // 2. Generate the per-build random key.
    Randomizer rng;
    ByteBuffer key(kKeySize);
    for (auto& b : key) b = rng.next_u8();

    // 3. Encrypt the target section in place.
    const uint32_t text_size = static_cast<uint32_t>(target.data.size());
    for (uint32_t i = 0; i < text_size; ++i) {
        target.data[i] ^= key[i % kKeySize];
    }

    // Allow the stub to decrypt in place.
    target.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

    // 4. Build the stub code + append the 256-byte key.
    auto [stub_buf, patches] = build_stub_bytes();
    if (stub_buf.size() != kStubCodeSize) {
        return std::unexpected(MxError(
            ProtectionErrorCode::pass_failed,
            std::format("PackerPass: stub code size mismatch ({} vs {})",
                stub_buf.size(), kStubCodeSize)));
    }
    const uint32_t key_offset_in_stub = kStubCodeSize;
    stub_buf.insert(stub_buf.end(), key.begin(), key.end());

    // Save the original entry point BEFORE we add the new section — the
    // stub's jmp rel32 needs to land on it.
    const Rva oep_rva = ctx.pe_image().entry_point_rva();
    const Rva text_rva = target.virtual_address;

    // 5. Add the .mxpack section and figure out its RVA.
    constexpr uint32_t pack_characteristics =
        pe::IMAGE_SCN_CNT_CODE |
        pe::IMAGE_SCN_MEM_EXECUTE |
        pe::IMAGE_SCN_MEM_READ;

    SectionManager sec_mgr(ctx.pe_image());
    auto add_res = sec_mgr.add_section(
        ".mxpack",
        ByteView{stub_buf.data(), stub_buf.size()},
        pack_characteristics);
    if (!add_res) {
        return std::unexpected(add_res.error());
    }

    const uint32_t pack_idx = *add_res;
    auto& pack_sec = ctx.pe_image().sections()[pack_idx];
    const Rva stub_rva = pack_sec.virtual_address;

    ctx.log_fmt("PackerPass: секция .mxpack добавлена: RVA=0x{:08X}, размер={} байт",
        stub_rva, static_cast<uint32_t>(pack_sec.data.size()));

    // 6. Patch the four rel32 placeholders.
    //
    // For each `lea reg, [rip + rel32]` and the final `jmp rel32`, the rel32
    // is computed from the instruction's END (= patch_offset + 4) to the
    // target. All offsets below are RVA-relative so we can subtract directly.

    // lea rdi, [rip + rel] → target = .text
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_text_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(text_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_text_at, rel);
    }

    // lea rsi, [rip + rel] → target = embedded key (inside stub)
    {
        const Rva lea_end_rva = stub_rva + patches.rel_to_key_at + 4;
        const Rva key_rva     = stub_rva + key_offset_in_stub;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(key_rva) - static_cast<int64_t>(lea_end_rva));
        write_i32(pack_sec.data, patches.rel_to_key_at, rel);
    }

    // mov ecx, imm32 → text_size
    write_i32(pack_sec.data, patches.text_size_at, static_cast<int32_t>(text_size));

    // jmp rel32 → OEP
    {
        const Rva jmp_end_rva = stub_rva + patches.rel_to_oep_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(oep_rva) - static_cast<int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, patches.rel_to_oep_at, rel);
    }

    // 7. Point the PE entry at the stub. Update both the cached value and
    //    the NT header field so PeBuilder emits the redirected OEP.
    ctx.pe_image().set_entry_point_rva(stub_rva);
    std::visit([&](auto& nt) {
        nt.OptionalHeader.AddressOfEntryPoint = stub_rva;
    }, ctx.pe_image().nt_headers());

    ctx.log_fmt("PackerPass: OEP перенаправлен 0x{:08X} -> 0x{:08X}",
        oep_rva, stub_rva);
    ctx.log("PackerPass: упаковка завершена");
    return {};
}

} // namespace mx
