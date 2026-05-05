/**
 * @file string_trampoline_codegen.cpp
 * @brief Implementation of `emit_trampoline` — the per-xref trampoline
 *        emitter.
 *
 * @details Extracted from `string_decryptor_codegen.cpp`. Each
 *          trampoline replaces a `lea target, [rip+disp32]` at the
 *          call site: the rewriter overwrites the LEA with `call
 *          trampoline`, and the trampoline preserves volatile
 *          registers, calls `mx_str_get`, and delivers the decrypted
 *          pointer into the original LEA's destination register.
 */

#include "mxprotector/protection/string/string_decryptor_codegen.hpp"

#include "mxprotector/core/asm_builder.hpp"

#include <cassert>
#include <cstdint>

namespace mx::string_protect {

namespace {

/// Stack slot (offset from rsp) of the saved copy of a volatile GPR
/// inside the trampoline, measured at the point where the `mov
/// [rsp+slot], rax` patch fires. Push order is:
///   push rax   (first after pushfq, deepest in stack)
///   push rcx
///   push rdx
///   push r8
///   push r9
///   push r10
///   push r11   (last, top of stack)
/// After all seven pushes, the top of stack holds r11 (slot 0), and
/// rax is eight slots below that at slot 48.
constexpr uint8_t volatile_stack_slot(GprIndex gpr) noexcept {
    switch (gpr) {
        case kGprRax: return 48;
        case kGprRcx: return 40;
        case kGprRdx: return 32;
        case kGprR8:  return 24;
        case kGprR9:  return 16;
        case kGprR10: return 8;
        case kGprR11: return 0;
        default:      return 0;  // unreachable — caller checks is_volatile
    }
}

/// `mov qword [rsp + slot], rax` — 5 bytes.
/// REX.W (0x48) + 0x89 + ModRM(01 000 100 = 0x44, SIB follows) +
/// SIB(00 100 100 = 0x24, base=rsp no index) + disp8 = slot.
void emit_mov_stack_slot_rax(std::vector<uint8_t>& c, uint8_t slot) {
    c.push_back(0x48);
    c.push_back(0x89);
    c.push_back(0x44);
    c.push_back(0x24);
    c.push_back(slot);
}

/// `mov target, rax` — 3 bytes — for a non-volatile GPR target.
/// Low regs (rbx/rbp/rsi/rdi) get REX 0x48; extended regs
/// (r12..r15) get REX 0x49 (REX.B set). ModRM is always
/// 11 000 <target_low3>, where reg field = rax = 0.
void emit_mov_reg_rax(std::vector<uint8_t>& c, GprIndex target) {
    const bool     ext   = target >= 8;
    const uint8_t  rex   = ext ? 0x49 : 0x48;
    const uint8_t  rm    = static_cast<uint8_t>(target & 0x7);
    const uint8_t  modrm = static_cast<uint8_t>(0xC0 | rm);
    c.push_back(rex);
    c.push_back(0x89);
    c.push_back(modrm);
}

} // namespace

EmittedTrampoline emit_trampoline(const TrampolineRequest& req)
{
    assert(req.target_reg != kGprRsp && "rsp is not a valid LEA target");
    assert(req.target_reg < 16       && "target must be a valid x64 GPR");

    EmittedTrampoline out;
    out.code.reserve(kTrampolineSizeVolatile);
    auto& c = out.code;

    // ---- Prologue: pushfq + 7 volatile pushes (12 bytes total) ----
    c.push_back(0x9C);                          // pushfq
    c.push_back(0x50);                          // push rax
    c.push_back(0x51);                          // push rcx
    c.push_back(0x52);                          // push rdx
    c.push_back(0x41); c.push_back(0x50);       // push r8
    c.push_back(0x41); c.push_back(0x51);       // push r9
    c.push_back(0x41); c.push_back(0x52);       // push r10
    c.push_back(0x41); c.push_back(0x53);       // push r11

    // ---- mov ecx, imm32 (string_id) (5 bytes) ----
    c.push_back(0xB9);
    const uint32_t id = req.string_id;
    c.push_back(static_cast<uint8_t>(id         & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 8)  & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 16) & 0xFF));
    c.push_back(static_cast<uint8_t>((id >> 24) & 0xFF));

    // ---- call rel32 (mx_str_get) (5 bytes) ----
    c.push_back(asm64::kCallRel32);
    out.call_rel32_offset = c.size();
    c.push_back(0x00); c.push_back(0x00); c.push_back(0x00); c.push_back(0x00);

    // ---- Deliver result to target ----
    if (is_volatile_gpr(req.target_reg)) {
        // Patch the saved slot on the stack so the matching pop
        // below restores `target = rax (pointer)`.
        emit_mov_stack_slot_rax(c, volatile_stack_slot(req.target_reg));
    } else {
        // Direct write. The LEA we replaced was going to clobber
        // target, so there's nothing to preserve.
        emit_mov_reg_rax(c, req.target_reg);
    }

    // ---- Epilogue: 7 pops (reverse order) + popfq + ret ----
    c.push_back(0x41); c.push_back(0x5B);       // pop r11
    c.push_back(0x41); c.push_back(0x5A);       // pop r10
    c.push_back(0x41); c.push_back(0x59);       // pop r9
    c.push_back(0x41); c.push_back(0x58);       // pop r8
    c.push_back(0x5A);                          // pop rdx
    c.push_back(0x59);                          // pop rcx
    c.push_back(0x58);                          // pop rax
    c.push_back(0x9D);                          // popfq
    c.push_back(asm64::kRet);                   // ret

    assert(c.size() == trampoline_size_for(req.target_reg));
    return out;
}

} // namespace mx::string_protect
