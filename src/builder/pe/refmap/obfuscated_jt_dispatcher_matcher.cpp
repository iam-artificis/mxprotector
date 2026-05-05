/**
 * @file obfuscated_jt_dispatcher_matcher.cpp
 * @brief Implementation — see `obfuscated_jt_dispatcher_matcher.hpp`.
 *
 * Owns the byte-level pattern matchers for the 7-instruction
 * obfuscated jump-table dispatcher and the top-level scan that
 * accumulates matches across every code section. Behaviour is
 * byte-for-byte identical to the inline implementation that lived
 * in `obfuscated_jt_scanner.cpp` before R10.
 */

#include "obfuscated_jt_dispatcher_matcher.hpp"

#include <algorithm>
#include <cstdint>
#include <unordered_set>

#include <Zydis/Zydis.h>

namespace mx::pe::refmap {

namespace {

[[nodiscard]] bool is_gpr64(ZydisRegister reg) noexcept {
    return reg >= ZYDIS_REGISTER_RAX && reg <= ZYDIS_REGISTER_R15;
}

/// `lea base, [rip + disp32]` — capture destination register and
/// computed JT base RVA. Returns false on any mismatch.
[[nodiscard]] bool match_lea_rip(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    Rva                            insn_rva,
    Rva&                           out_jt_rva,
    ZydisRegister&                 out_base) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_LEA)        return false;
    if (insn.operand_count_visible < 2)             return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER) return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY)   return false;
    if (ops[1].mem.base != ZYDIS_REGISTER_RIP)      return false;
    if (insn.raw.disp.size != 32)                   return false;
    if (!is_gpr64(ops[0].reg.value))                return false;

    const std::int64_t target =
        static_cast<std::int64_t>(insn_rva) +
        static_cast<std::int64_t>(insn.length) +
        insn.raw.disp.value;
    if (target < 0)                                  return false;

    out_jt_rva = static_cast<Rva>(target);
    out_base   = ops[0].reg.value;
    return true;
}

/// `mov eax, dword ptr [base + rax*4]` — strict shape, with `eax`
/// as destination and `rax` as scaled index. Displacement may be
/// 0 or 8 bits with value 0 (the disp8=0 variant is mandatory when
/// `base == r13` due to x64 SIB encoding rules).
[[nodiscard]] bool match_mov_eax_base_rax4(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    ZydisRegister                  base) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_MOV)         return false;
    if (insn.operand_count_visible < 2)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[0].reg.value != ZYDIS_REGISTER_EAX)      return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_MEMORY)    return false;
    if (ops[1].size != 32)                           return false;
    if (ops[1].mem.base  != base)                    return false;
    if (ops[1].mem.index != ZYDIS_REGISTER_RAX)      return false;
    if (ops[1].mem.scale != 4)                       return false;
    // Displacement, if present, must be zero — the dispatcher does
    // not slice into the JT.
    if (insn.raw.disp.size != 0 && insn.raw.disp.value != 0)
        return false;
    return true;
}

/// `xor eax, imm32` — capture the 32-bit key. Returns false on the
/// stack-key variant (`xor eax, [rsp + disp8]`) since we cannot
/// statically extract the key there.
[[nodiscard]] bool match_xor_eax_imm32(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    std::uint32_t&                 out_key) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_XOR)         return false;
    if (insn.operand_count_visible < 2)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[0].reg.value != ZYDIS_REGISTER_EAX)      return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE) return false;
    out_key = static_cast<std::uint32_t>(ops[1].imm.value.u);
    return true;
}

/// `movsxd rax, eax` — exact register pair.
[[nodiscard]] bool match_movsxd_rax_eax(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_MOVSXD)      return false;
    if (insn.operand_count_visible < 2)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[0].reg.value != ZYDIS_REGISTER_RAX)      return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[1].reg.value != ZYDIS_REGISTER_EAX)      return false;
    return true;
}

/// `add base, rax` — exact (no immediate, no memory).
[[nodiscard]] bool match_add_base_rax(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    ZydisRegister                  base) noexcept
{
    if (insn.mnemonic != ZYDIS_MNEMONIC_ADD)         return false;
    if (insn.operand_count_visible < 2)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[1].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[0].reg.value != base)                    return false;
    if (ops[1].reg.value != ZYDIS_REGISTER_RAX)      return false;
    return true;
}

/// `jmp base` (final) or `push base` (followed by `ret`).
enum class TailKind : std::uint8_t { Jmp, PushRet };

[[nodiscard]] bool match_dispatcher_tail(
    const ZydisDecodedInstruction& insn,
    const ZydisDecodedOperand*     ops,
    ZydisRegister                  base,
    TailKind&                      out_kind) noexcept
{
    if (insn.operand_count_visible < 1)              return false;
    if (ops[0].type != ZYDIS_OPERAND_TYPE_REGISTER)  return false;
    if (ops[0].reg.value != base)                    return false;
    if (insn.mnemonic == ZYDIS_MNEMONIC_JMP) {
        out_kind = TailKind::Jmp;
        return true;
    }
    if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH) {
        out_kind = TailKind::PushRet;
        return true;
    }
    return false;
}

/// Helper bundle: decode-and-advance one instruction. Returns false
/// at end-of-buffer or on Zydis decode failure.
[[nodiscard]] bool decode_one(
    ZydisDecoder&             decoder,
    const std::uint8_t*       buf,
    std::size_t               buf_size,
    std::size_t&              offset,
    ZydisDecodedInstruction&  insn,
    ZydisDecodedOperand*      ops)
{
    if (offset >= buf_size) return false;
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
            &decoder, buf + offset, buf_size - offset, &insn, ops)))
    {
        return false;
    }
    offset += insn.length;
    return true;
}

/// Try to recognise the 6- or 7-instruction dispatcher pattern
/// starting at `start_offset`. Captures `(jt_base_rva, key)` on
/// match.
[[nodiscard]] bool try_match_dispatcher(
    ZydisDecoder&        decoder,
    const std::uint8_t*  buf,
    std::size_t          buf_size,
    std::size_t          start_offset,
    Rva                  insn_rva_at_start,
    DispatcherSite&      out)
{
    std::size_t offset = start_offset;

    // 1. LEA base, [rip + disp32].
    ZydisDecodedInstruction i1{};
    ZydisDecodedOperand     o1[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i1, o1)) return false;
    Rva           jt_base = 0;
    ZydisRegister base    = ZYDIS_REGISTER_NONE;
    if (!match_lea_rip(i1, o1, insn_rva_at_start, jt_base, base)) return false;

    // 2. MOV eax, [base + rax*4].
    ZydisDecodedInstruction i2{};
    ZydisDecodedOperand     o2[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i2, o2)) return false;
    if (!match_mov_eax_base_rax4(i2, o2, base))               return false;

    // 3. XOR eax, imm32 (ONLY this variant — stack key skipped).
    ZydisDecodedInstruction i3{};
    ZydisDecodedOperand     o3[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i3, o3)) return false;
    std::uint32_t key = 0;
    if (!match_xor_eax_imm32(i3, o3, key))                    return false;

    // 4. MOVSXD rax, eax.
    ZydisDecodedInstruction i4{};
    ZydisDecodedOperand     o4[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i4, o4)) return false;
    if (!match_movsxd_rax_eax(i4, o4))                        return false;

    // 5. ADD base, rax.
    ZydisDecodedInstruction i5{};
    ZydisDecodedOperand     o5[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i5, o5)) return false;
    if (!match_add_base_rax(i5, o5, base))                    return false;

    // 6. JMP base   OR   PUSH base + RET.
    ZydisDecodedInstruction i6{};
    ZydisDecodedOperand     o6[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!decode_one(decoder, buf, buf_size, offset, i6, o6)) return false;
    TailKind tail{};
    if (!match_dispatcher_tail(i6, o6, base, tail))           return false;

    if (tail == TailKind::PushRet) {
        ZydisDecodedInstruction i7{};
        ZydisDecodedOperand     o7[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!decode_one(decoder, buf, buf_size, offset, i7, o7)) return false;
        if (i7.mnemonic != ZYDIS_MNEMONIC_RET)                    return false;
    }

    out = DispatcherSite{ .jt_base_rva = jt_base, .key = key };
    return true;
}

} // anonymous namespace

std::vector<DispatcherSite> find_dispatchers(const PeImage& image) {
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,
                     ZYDIS_MACHINE_MODE_LONG_64,
                     ZYDIS_STACK_WIDTH_64);

    std::vector<DispatcherSite> sites;
    sites.reserve(64);
    std::unordered_set<Rva> seen_bases;

    for (const auto& sec : image.sections()) {
        if (!sec.is_code() || sec.data.empty()) continue;

        const std::size_t buf_size = std::min(
            sec.data.size(),
            static_cast<std::size_t>(sec.virtual_size));
        const std::uint8_t* buf = sec.data.data();

        std::size_t offset = 0;
        while (offset < buf_size) {
            const Rva insn_rva = static_cast<Rva>(
                sec.virtual_address + offset);
            DispatcherSite site{};
            if (try_match_dispatcher(
                    decoder, buf, buf_size, offset, insn_rva, site))
            {
                if (seen_bases.insert(site.jt_base_rva).second) {
                    sites.push_back(site);
                }
            }

            // Always advance by exactly one decoded instruction so
            // overlapping dispatchers in densely packed code blocks
            // are not skipped over.
            ZydisDecodedInstruction skip{};
            ZydisDecodedOperand     skip_ops[ZYDIS_MAX_OPERAND_COUNT]{};
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(
                    &decoder, buf + offset, buf_size - offset,
                    &skip, skip_ops)))
            {
                ++offset;
                continue;
            }
            offset += skip.length;
        }
    }

    std::sort(sites.begin(), sites.end(),
              [](const DispatcherSite& a, const DispatcherSite& b) {
                  return a.jt_base_rva < b.jt_base_rva;
              });
    return sites;
}

} // namespace mx::pe::refmap
