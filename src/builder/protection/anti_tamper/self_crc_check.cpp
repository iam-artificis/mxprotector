/**
 * @file self_crc_check.cpp
 * @brief Anti-tamper probe — CRC32C of the already-emitted entry-stub
 *        prefix, verified at runtime against a deferred expected value.
 *
 * ### What this catches
 *
 * A reverse engineer setting a software breakpoint in the entry stub
 * rewrites one byte of our emitted code with `0xCC` (`INT 3`). Debuggers
 * and dynamic instrumentation frameworks typically install breakpoints
 * this way because hardware DR slots are limited to four. The CRC of
 * the patched byte range no longer matches the expected value, the
 * check corrupts the handler-table key slot, and every subsequent VM
 * dispatch decrypts the wrong handler offset → jump to garbage →
 * access violation.
 *
 * Runtime self-patching tools (Frida inline hooks, Scylla-style code
 * injection, trampoline installation via `WriteProcessMemory`) all
 * trigger the same mismatch. The check is blind to which byte
 * changed — any tamper within the CRC range is caught.
 *
 * ### CRC coverage
 *
 * The CRC range is `[entry_offset, check_start)` — every entry-stub
 * byte that was emitted BEFORE the Self-CRC check itself. That
 * includes `pushfq`, the G7 pad pushes, the 16 reg pushes, the
 * rolling-key seed, the RFLAGS scramble, the ImageBase MBA chain
 * with integrity check, every previously-picked anti-emulation
 * check, and — if present — the Hell's Gate SSN resolver.
 *
 * ### Why the expected CRC is deferred
 *
 * The X64 backend applies several post-hoc patches in its final
 * pass AFTER the anti-tamper loop has been emitted:
 *
 *   * `table_patches`: every `lea reg, [rip + rel32]` that points at
 *     the handler table gets its rel32 fixed up once the table
 *     offset is known. Including the `integrity_table_lea_patch`
 *     that lives INSIDE the imagebase-key block, i.e. INSIDE the
 *     CRC range.
 *
 *   * `integrity_expected_patch`: the imm32 that lands in
 *     `xor edx, <expected_sum>`. Also inside the CRC range.
 *
 * If the check baked its expected CRC at emit time, those
 * placeholders would still be zero, and the expected value would
 * not match what the runtime CRC reads (the runtime CRC sees the
 * finalised bytes with real rel32s). Every build would therefore
 * false-positive.
 *
 * The fix is to defer the expected-CRC computation until every
 * other patch has already been applied. The check emits a
 * placeholder `cmp eax, 0x00000000` at emit time, records the
 * placeholder offset and CRC range via a `SelfCrcPatchRecord`, and
 * `finalize_self_crc_patches` computes the real CRC over the
 * finalised buffer in the X64 backend's Step 4.
 *
 * ### CRC32C algorithm
 *
 * Uses the x86-64 hardware `crc32` instruction (SSE4.2, universal
 * on every x86-64 CPU since Nehalem/K10 ~2008). The instruction
 * computes CRC with the Castagnoli polynomial 0x82F63B78
 * (reflected form). Init value and final XOR are the caller's
 * responsibility — we use the standard
 * `init = 0xFFFFFFFF, final_xor = 0xFFFFFFFF` convention.
 *
 * Build-time expected value uses the matching software CRC32C
 * (`crc32c_sw`), which applies exactly the same polynomial, init,
 * and final XOR so that the two sides agree.
 *
 * Byte sequence (~51 bytes):
 *
 *     48 8D 35 <neg_rel32>           lea  rsi, [rip + rel32]      ; → entry start
 *     B9 <len32>                     mov  ecx, <length>
 *     B8 FF FF FF FF                 mov  eax, 0xFFFFFFFF         ; crc init
 *   .loop:
 *     F2 0F 38 F0 06                 crc32 eax, byte [rsi]
 *     48 FF C6                       inc  rsi
 *     FF C9                          dec  ecx
 *     75 F4                          jnz  .loop                   ; rel8 = -12
 *     F7 D0                          not  eax                     ; final xor
 *     3D <placeholder>               cmp  eax, <deferred crc>
 *     74 07                          je   .clean
 *     B8 <mask>                      mov  eax, <corruption>
 *     EB 02                          jmp  .apply
 *   .clean:
 *     31 C0                          xor  eax, eax
 *   .apply:
 *     31 44 24 <disp8>               xor  [rsp + key_disp], eax
 *
 * Register usage: clobbers rax, rcx, rsi. All three are saved in
 * VM-context slots from the entry stub's push sequence, so
 * clobbering is harmless.
 */

#include "mxprotector/protection/anti_tamper/self_crc_check.hpp"

#include <cstring>
#include <memory>

#include "mxprotector/protection/anti_tamper/check.hpp"

namespace mx::anti_tamper {

namespace {

/// One round of CRC32C (Castagnoli polynomial, reflected form).
/// Matches the hardware `crc32 eax, byte [reg]` instruction's
/// behaviour exactly when you wrap it in the
/// `init = 0xFFFFFFFF, final_xor = 0xFFFFFFFF` convention below.
constexpr uint32_t crc32c_update(uint32_t crc, uint8_t byte) noexcept {
    crc ^= byte;
    for (int i = 0; i < 8; ++i) {
        crc = (crc >> 1) ^ ((crc & 1u) ? 0x82F63B78u : 0u);
    }
    return crc;
}

} // anonymous namespace

uint32_t crc32c_sw(const uint8_t* data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc = crc32c_update(crc, data[i]);
    }
    return crc ^ 0xFFFFFFFFu;
}

void finalize_self_crc_patches(
    RawEmitter& e,
    std::span<const SelfCrcPatchRecord> patches) noexcept
{
    for (const auto& r : patches) {
        if (r.length == 0 || r.range_start + r.length > e.buf.size()) continue;
        const uint32_t crc = crc32c_sw(e.buf.data() + r.range_start, r.length);
        if (r.placeholder_offset + 4 > e.buf.size()) continue;
        std::memcpy(e.buf.data() + r.placeholder_offset, &crc, 4);
    }
}

class SelfCrcCheck final : public ICheck {
public:
    void emit(RawEmitter& e,
              int32_t key_slot_disp,
              Randomizer& rng,
              const CheckContext& ctx) const override
    {
        const uint32_t corruption = rng.next_u32() | 1u;

        // CRC range: the entry-stub bytes emitted before this check.
        const size_t range_start = ctx.entry_offset;
        const size_t range_end   = e.size();

        // Safety: no bytes to CRC? Degrade to a safe no-op so the
        // key slot stays intact. This path is only exercised by
        // unit tests that construct a check without an entry stub.
        if (range_end <= range_start) {
            e.u8(0x31); e.u8(0xC0);          // xor eax, eax
            e.u8(0x31); e.u8(0x44); e.u8(0x24);
            e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));
            (void)rng;
            (void)corruption;
            return;
        }
        const size_t length = range_end - range_start;

        // --- lea rsi, [rip + rel32]  → points at entry_offset ---
        e.u8(0x48); e.u8(0x8D); e.u8(0x35);
        const size_t rip_after_lea = e.size() + 4;
        const int64_t rel64 =
            static_cast<int64_t>(range_start) -
            static_cast<int64_t>(rip_after_lea);
        e.u32(static_cast<uint32_t>(rel64));

        // mov ecx, <length>                  B9 imm32
        e.u8(0xB9);
        e.u32(static_cast<uint32_t>(length));

        // mov eax, 0xFFFFFFFF                B8 FF FF FF FF
        e.u8(0xB8); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF); e.u8(0xFF);

        // .loop:
        const size_t label_loop = e.size();
        // crc32 eax, byte [rsi]              F2 0F 38 F0 06
        e.u8(0xF2); e.u8(0x0F); e.u8(0x38); e.u8(0xF0); e.u8(0x06);
        // inc rsi                            48 FF C6
        e.u8(0x48); e.u8(0xFF); e.u8(0xC6);
        // dec ecx                            FF C9
        e.u8(0xFF); e.u8(0xC9);
        // jnz .loop                          75 rel8
        e.u8(0x75);
        {
            const size_t jnz_end = e.size() + 1;
            const int delta = static_cast<int>(label_loop) -
                              static_cast<int>(jnz_end);
            e.u8(static_cast<uint8_t>(static_cast<int8_t>(delta)));
        }

        // not eax                            F7 D0
        e.u8(0xF7); e.u8(0xD0);

        // cmp eax, <expected>                3D imm32
        // The imm32 is a placeholder that `finalize_self_crc_patches`
        // fills in once all other patches have been applied.
        e.u8(0x3D);
        const size_t placeholder_offset = e.size();
        e.u32(0);

        // Register the patch record so the X64 backend can finalise
        // this CRC after every other post-hoc patch. If the context
        // has no collector (unit tests), the CRC stays at zero —
        // which means the check will always report "mismatch" and
        // always corrupt the key, so unit tests that construct a
        // check in isolation MUST set the slot to zero as a dummy
        // value and not execute the emitted bytes.
        if (ctx.self_crc_patches != nullptr) {
            ctx.self_crc_patches->push_back({
                placeholder_offset,
                range_start,
                length
            });
        }

        // je short .clean                    74 rel8 (patched)
        e.u8(0x74);
        const size_t patch_je_clean = e.size();
        e.u8(0x00);

        // mov eax, <corruption>              B8 imm32
        e.u8(0xB8);
        e.u32(corruption);
        // jmp short .apply                   EB rel8 (patched)
        e.u8(0xEB);
        const size_t patch_jmp_apply = e.size();
        e.u8(0x00);

        // .clean:
        const size_t label_clean = e.size();
        // xor eax, eax                       31 C0
        e.u8(0x31); e.u8(0xC0);

        // .apply:
        const size_t label_apply = e.size();
        // xor [rsp + disp8], eax             31 44 24 disp8
        e.u8(0x31); e.u8(0x44); e.u8(0x24);
        e.u8(static_cast<uint8_t>(static_cast<int8_t>(key_slot_disp)));

        // Back-patch the two forward rel8 jumps.
        {
            const int delta = static_cast<int>(label_clean) -
                              static_cast<int>(patch_je_clean + 1);
            e.buf[patch_je_clean] =
                static_cast<uint8_t>(static_cast<int8_t>(delta));
        }
        {
            const int delta = static_cast<int>(label_apply) -
                              static_cast<int>(patch_jmp_apply + 1);
            e.buf[patch_jmp_apply] =
                static_cast<uint8_t>(static_cast<int8_t>(delta));
        }
    }

    [[nodiscard]] const char* name() const noexcept override {
        return "self_crc";
    }
};

std::unique_ptr<ICheck> make_self_crc_check() {
    return std::make_unique<SelfCrcCheck>();
}

} // namespace mx::anti_tamper
