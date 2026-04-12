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

#include <Zydis/Zydis.h>

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

/// Approximate size of the stub code (before the key). The actual size varies
/// a little across builds because the push/pop and setup order is randomised,
/// but the patch offsets are tracked dynamically so this is only a sanity
/// reference for documentation.
///
/// Layout (all sizes in bytes):
///   push rdi/rsi/rcx/rdx/rax          = 5
///   mov  rax, gs:[0x60]                = 9    — read PEB
///   movzx eax, byte [rax+2]            = 4    — BeingDebugged (0 or 1)
///   mov  edx, eax                       = 2    — edx = 0 normally, 1 under a dbg
///   lea  rdi, [rip + rel32]             = 7
///   lea  rsi, [rip + rel32]             = 7
///   mov  ecx, imm32                     = 5
///   .loop:
///     mov  al, [rdi]                    = 2
///     xor  al, [rsi + rdx]              = 3
///     mov  [rdi], al                    = 2
///     inc  rdi                          = 3
///     inc  dl                           = 2
///     dec  rcx                          = 3
///     jnz  .loop                        = 2
///   pop  rax/rdx/rcx/rsi/rdi            = 5
///   jmp  rel32                          = 5
///   -------------------------------------
///   total                               = 66
///
/// The anti-debug is woven *into* the decryption: if the process is being
/// debugged, edx starts at 1 instead of 0 and the entire key stream is
/// shifted by one byte, producing garbage on the first instruction executed.
/// A reverser cannot simply NOP the check — they must also un-shift the
/// byte counter, which would require detecting that the shift is present.
constexpr uint32_t kStubCodeSize = 66;

struct StubPatches {
    uint32_t rel_to_text_at;       ///< patch offset inside stub (rel32 from end-of-lea to .text)
    uint32_t rel_to_key_at;        ///< patch offset (rel32 from end-of-lea to embedded key)
    uint32_t rel_to_oep_at;        ///< patch offset (rel32 from end-of-jmp to OEP + stolen_size)
    uint32_t text_size_at;         ///< patch offset of the `mov ecx, imm32` immediate
    uint32_t stolen_bytes_offset;  ///< offset of the first byte of the embedded stolen payload
};

/// Minimum number of bytes we want to steal from the OEP. We walk whole
/// instructions so the actual stolen size may be larger.
constexpr uint32_t kMinStolenBytes = 10;
/// Upper bound on stolen bytes — prevents extracting so much code that the
/// stub grows unreasonably or the check for safe instructions becomes fragile.
constexpr uint32_t kMaxStolenBytes = 64;

/// One rel32 fix-up inside the stolen-bytes payload: the rel32 target was
/// originally `original_target_rva`; after the bytes move into the stub the
/// rel32 at `offset_in_stolen` (4 bytes) must be rewritten to keep pointing
/// at that RVA. Currently only CALL rel32 patches are produced.
struct StolenReloc {
    uint32_t offset_in_stolen;    ///< offset of rel32 within stolen_bytes
    uint32_t instr_end_in_stolen; ///< byte just after the full instruction
    Rva      original_target_rva; ///< absolute target RVA (stays constant)
};

struct StolenPlan {
    uint32_t                 size = 0;
    std::vector<StolenReloc> relocs;
};

/// Scan OEP for instructions that can be safely lifted into the stub.
/// Allows:
///   - plain GPR/ALU instructions
///   - CALL rel32 (will be rewritten after move)
/// Rejects:
///   - JMP/JCC (stubs don't loop — a taken branch would escape unresolved)
///   - RET (ends the OEP sequence)
///   - RIP-relative memory operands (cannot be fixed up generically)
[[nodiscard]] StolenPlan plan_stolen_bytes(ByteView text_bytes,
                                           uint32_t oep_offset_in_text,
                                           Rva oep_rva)
{
    StolenPlan result;
    if (oep_offset_in_text >= text_bytes.size()) return result;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

    size_t pos = oep_offset_in_text;
    while (result.size < kMinStolenBytes) {
        if (pos >= text_bytes.size()) { result.size = 0; result.relocs.clear(); return result; }
        const size_t remain = text_bytes.size() - pos;

        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                &decoder, text_bytes.data() + pos, remain, &insn, operands))) {
            return {};
        }

        // Reject branches/ret outright — they leave the stolen sequence.
        if (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            insn.meta.category == ZYDIS_CATEGORY_RET) {
            return {};
        }

        // RIP-relative memory references break when we move the bytes.
        for (ZyanU8 i = 0; i < insn.operand_count; ++i) {
            const auto& op = operands[i];
            if (op.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                op.mem.base == ZYDIS_REGISTER_RIP) {
                return {};
            }
        }

        // CALL rel32 — record a fix-up so the absolute target survives.
        if (insn.meta.category == ZYDIS_CATEGORY_CALL) {
            // Only the rel32 form (E8 rel32) is supported here. Indirect calls
            // (FF /2) would need a different encoding change.
            if (insn.length != 5 || text_bytes[pos] != 0xE8) return {};

            int32_t rel32 = 0;
            std::memcpy(&rel32, text_bytes.data() + pos + 1, 4);
            const Rva target_rva = static_cast<Rva>(
                static_cast<int64_t>(oep_rva) +
                static_cast<int64_t>(pos - oep_offset_in_text) +
                5 + rel32);

            StolenReloc r{};
            r.offset_in_stolen    = result.size + 1;
            r.instr_end_in_stolen = result.size + 5;
            r.original_target_rva = target_rva;
            result.relocs.push_back(r);
        }

        pos += insn.length;
        result.size += insn.length;
        if (result.size > kMaxStolenBytes) return {};
    }
    return result;
}

/// Build the stub code bytes (without patching rel32s yet) and report where
/// the placeholders need to be filled in. Per-build polymorphism:
///
///   - The order of the 5 push (and mirrored pops) is randomised, so no two
///     builds save registers in the same shape.
///   - The order of the three setup instructions (lea rdi, lea rsi, mov ecx)
///     is randomised — they are independent so any order is correct.
[[nodiscard]] std::pair<ByteBuffer, StubPatches> build_stub_bytes(
    Randomizer& rng,
    ByteView stolen_bytes)
{
    ByteBuffer buf;
    buf.reserve(128 + stolen_bytes.size() + kKeySize);

    auto u8 = [&](uint8_t v) { buf.push_back(v); };
    auto u32 = [&](uint32_t v) {
        buf.push_back(static_cast<uint8_t>(v));
        buf.push_back(static_cast<uint8_t>(v >> 8));
        buf.push_back(static_cast<uint8_t>(v >> 16));
        buf.push_back(static_cast<uint8_t>(v >> 24));
    };

    // Randomised push/pop register order. The same permutation is used for
    // pushes (top-down) and pops (reverse) so the stack is balanced.
    std::array<uint8_t, 5> save_order{0x50 /*rax*/, 0x51 /*rcx*/, 0x52 /*rdx*/,
                                       0x56 /*rsi*/, 0x57 /*rdi*/};
    std::shuffle(save_order.begin(), save_order.end(), rng.engine());

    for (uint8_t op : save_order) u8(op);

    StubPatches patches{};

    // Anti-debug: read PEB.BeingDebugged into rdx. Normally 0, a debugger
    // sets it to 1 — in that case our initial key-stream index becomes 1
    // and the whole decrypted stream is off by one byte, silently corrupting
    // the program. No explicit jump to patch.
    //
    //   mov rax, gs:[0x60]         ; 65 48 8B 04 25 60 00 00 00
    //   movzx eax, byte [rax+2]    ; 0F B6 40 02
    //   mov edx, eax                ; 89 C2
    u8(0x65); u8(0x48); u8(0x8B); u8(0x04); u8(0x25);
    u8(0x60); u8(0x00); u8(0x00); u8(0x00);
    u8(0x0F); u8(0xB6); u8(0x40); u8(0x02);
    u8(0x89); u8(0xC2);

    // Randomised setup ordering. The three gadgets all write independent
    // registers (rdi, rsi, rcx) so any permutation is valid.
    enum Gadget : uint8_t { lea_rdi = 0, lea_rsi = 1, mov_ecx = 2 };
    std::array<Gadget, 3> gadgets{lea_rdi, lea_rsi, mov_ecx};
    std::shuffle(gadgets.begin(), gadgets.end(), rng.engine());

    for (Gadget g : gadgets) {
        switch (g) {
            case lea_rdi:
                u8(0x48); u8(0x8D); u8(0x3D);
                patches.rel_to_text_at = static_cast<uint32_t>(buf.size());
                u32(0);
                break;
            case lea_rsi:
                u8(0x48); u8(0x8D); u8(0x35);
                patches.rel_to_key_at = static_cast<uint32_t>(buf.size());
                u32(0);
                break;
            case mov_ecx:
                u8(0xB9);
                patches.text_size_at = static_cast<uint32_t>(buf.size());
                u32(0);
                break;
        }
    }

    // .loop: (target of jnz at bottom)
    const uint32_t loop_body_start = static_cast<uint32_t>(buf.size());

    //   mov al, [rdi]                       8A 07
    u8(0x8A); u8(0x07);
    //   xor al, [rsi + rdx*1]               32 04 16
    u8(0x32); u8(0x04); u8(0x16);
    //   mov [rdi], al                       88 07
    u8(0x88); u8(0x07);
    //   inc rdi                             48 FF C7
    u8(0x48); u8(0xFF); u8(0xC7);
    //   inc dl  — wraps at 256 (exactly the key length)    FE C2
    u8(0xFE); u8(0xC2);
    //   dec rcx                             48 FF C9
    u8(0x48); u8(0xFF); u8(0xC9);
    //   jnz .loop   (rel8 to loop_body_start)
    const uint32_t jnz_end = static_cast<uint32_t>(buf.size()) + 2;
    const int32_t  rel8    = static_cast<int32_t>(loop_body_start) -
                             static_cast<int32_t>(jnz_end);
    u8(0x75); u8(static_cast<uint8_t>(static_cast<int8_t>(rel8)));

    // Restore registers in reverse of the saved order (LIFO).
    for (auto it = save_order.rbegin(); it != save_order.rend(); ++it) {
        // Each push op (50..57) translates to the matching pop op (58..5F).
        u8(static_cast<uint8_t>(*it + 0x08));
    }

    // Stolen bytes: the first instructions of the original OEP have been
    // moved here. We execute them inline (rsp is now back to what the OEP
    // would have seen at entry) before jumping past the gap we punched in
    // the decrypted .text.
    patches.stolen_bytes_offset = static_cast<uint32_t>(buf.size());
    if (!stolen_bytes.empty()) {
        for (auto b : stolen_bytes) u8(b);
    }

    // jmp rel32   ; to OEP + stolen_size
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

    // 2. Plan stolen bytes: move the first instructions of OEP into the stub
    //    (before encryption) so a memory dump of the decrypted .text is
    //    missing its front. plan_stolen_bytes refuses unsafe sequences; in
    //    that case we skip stealing and keep the packer semantically
    //    identical. CALL rel32 sites are carried as relocs and fixed up
    //    once the stub section gets placed.
    const Rva oep_rva_initial = ctx.pe_image().entry_point_rva();
    StolenPlan stolen_plan;
    ByteBuffer stolen_bytes;
    if (oep_rva_initial >= target.virtual_address &&
        oep_rva_initial < target.virtual_address + target.virtual_size) {
        const uint32_t oep_off = oep_rva_initial - target.virtual_address;
        stolen_plan = plan_stolen_bytes(
            ByteView{target.data.data(), target.data.size()},
            oep_off, oep_rva_initial);
        if (stolen_plan.size > 0) {
            stolen_bytes.assign(
                target.data.begin() + oep_off,
                target.data.begin() + oep_off + stolen_plan.size);
            std::fill(target.data.begin() + oep_off,
                      target.data.begin() + oep_off + stolen_plan.size,
                      static_cast<uint8_t>(0xCC));
            ctx.log_fmt("PackerPass: украдено {} байт OEP (0x{:08X}), {} CALL-fixup",
                stolen_plan.size, oep_rva_initial,
                static_cast<uint32_t>(stolen_plan.relocs.size()));
        } else {
            ctx.log("PackerPass: OEP небезопасен для stolen bytes — пропуск");
        }
    }
    const uint32_t stolen_size = stolen_plan.size;

    // 3. Generate the per-build random key.
    Randomizer rng;
    ByteBuffer key(kKeySize);
    for (auto& b : key) b = rng.next_u8();

    // 4. Encrypt the target section in place.
    const uint32_t text_size = static_cast<uint32_t>(target.data.size());
    for (uint32_t i = 0; i < text_size; ++i) {
        target.data[i] ^= key[i % kKeySize];
    }

    // Allow the stub to decrypt in place.
    target.characteristics |= pe::IMAGE_SCN_MEM_WRITE;

    // 5. Build the stub code (now including stolen OEP bytes) + append the
    //    256-byte key. Size is not fixed because the stub is polymorphic.
    auto [stub_buf, patches] = build_stub_bytes(
        rng, ByteView{stolen_bytes.data(), stolen_bytes.size()});
    const uint32_t key_offset_in_stub = static_cast<uint32_t>(stub_buf.size());
    stub_buf.insert(stub_buf.end(), key.begin(), key.end());

    // The jmp rel32 lands AFTER the stolen bytes: OEP + stolen_size.
    const Rva oep_rva = oep_rva_initial + stolen_size;
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

    // jmp rel32 → OEP + stolen_size
    {
        const Rva jmp_end_rva = stub_rva + patches.rel_to_oep_at + 4;
        const int32_t rel = static_cast<int32_t>(
            static_cast<int64_t>(oep_rva) - static_cast<int64_t>(jmp_end_rva));
        write_i32(pack_sec.data, patches.rel_to_oep_at, rel);
    }

    // Fix up CALL rel32 inside the stolen bytes so each CALL still targets
    // its original .text function after the move into .mxpack.
    for (const auto& r : stolen_plan.relocs) {
        const uint32_t rel_abs_offset = patches.stolen_bytes_offset + r.offset_in_stolen;
        const uint32_t instr_end_abs  = patches.stolen_bytes_offset + r.instr_end_in_stolen;
        const Rva new_instr_end_rva   = stub_rva + instr_end_abs;
        const int32_t new_rel = static_cast<int32_t>(
            static_cast<int64_t>(r.original_target_rva) -
            static_cast<int64_t>(new_instr_end_rva));
        write_i32(pack_sec.data, rel_abs_offset, new_rel);
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
