/**
 * @file x64_vflags.hpp
 * @brief [BUILDER, x64] Polymorphic vEFLAGS scrambling for the x64 backend.
 *
 * The VM keeps the guest's RFLAGS in a per-region scrambled form
 * inside a stack slot:
 *
 *     stored = rol(real_rflags, vflags_rol) ^ vflags_key
 *
 * Each save / popfq / read-into-ecx site picks one of several
 * semantically-equivalent emission variants at random per build, so
 * a YARA-style signature cannot match all 60+ store sites and 20+
 * descramble sites in a sub-VM with one regex.
 *
 * The four variant enums and the corresponding emitters live here
 * because they are the most x64-flavoured part of the runtime — they
 * lean heavily on `pushfq`, `popfq`, `mov rax`, `xor imm32`, and
 * `[rsp + disp32]`. An arm64 backend will replace them entirely
 * (NZCV via MRS/MSR or via computed predicates in plain GPRs).
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/raw_emitter.hpp"

namespace mx::vm::x64 {

// ----------------------------------------------------------------------------
// Variant selectors
// ----------------------------------------------------------------------------

/// Variant for vEFLAGS store (write the scrambled flags to a slot).
enum class VflagsStoreV : uint8_t {
    RaxRolFirst = 0,  ///< pushfq; pop rax; rol eax,n; xor eax,key; mov slot,rax
    RaxXorFirst = 1,  ///< pushfq; pop rax; xor eax,ror(key,n); rol eax,n; mov slot,rax
    InPlace     = 2,  ///< pushfq; rol [rsp],n; xor [rsp],key; pop qword slot
    kCount      = 3
};

/// Variant for vEFLAGS descramble-then-popfq.
enum class VflagsPopfqV : uint8_t {
    RaxXorFirst = 0,  ///< mov eax,slot; xor eax,key; ror eax,n; push rax; popfq
    RaxRorFirst = 1,  ///< mov eax,slot; ror eax,n; xor eax,ror(key,n); push rax; popfq
    InPlace     = 2,  ///< push qword slot; xor [rsp],key; ror [rsp],n; popfq
    kCount      = 3
};

/// Variant for vEFLAGS descramble-into-ecx (used by VJCC bit testing).
enum class VflagsToEcxV : uint8_t {
    XorFirst = 0,     ///< mov ecx,slot; xor ecx,key; ror ecx,n
    RorFirst = 1,     ///< mov ecx,slot; ror ecx,n; xor ecx,ror(key,n)
    kCount   = 2
};

/// Variant for in-slot transforms (entry forward / exit reverse).
enum class VflagsInSlotV : uint8_t {
    RegXorFirst = 0,  ///< mov eax,[slot]; rol/ror; xor; mov [slot],rax  (rax scratch)
    RegRorFirst = 1,  ///< mov eax,[slot]; xor; rol/ror; mov [slot],rax  (rax scratch)
    MemXorFirst = 2,  ///< xor dword [slot],k; rol/ror dword [slot],n    (no scratch)
    MemRorFirst = 3,  ///< rol/ror dword [slot],n; xor dword [slot],k'   (no scratch)
    kCount      = 4
};

// ----------------------------------------------------------------------------
// Random selectors
// ----------------------------------------------------------------------------

[[nodiscard]] VflagsStoreV  pick_store_variant (Randomizer& rng);
[[nodiscard]] VflagsPopfqV  pick_popfq_variant (Randomizer& rng);
[[nodiscard]] VflagsToEcxV  pick_to_ecx_variant(Randomizer& rng);
[[nodiscard]] VflagsInSlotV pick_inslot_variant(Randomizer& rng);

// ----------------------------------------------------------------------------
// Emitters
// ----------------------------------------------------------------------------

/// Emit one of the polymorphic store variants. Writes
/// `rol(real_rflags, vflags_rol) ^ vflags_key` into `[rsp + rflags_disp]`.
/// Clobbers rax in the Rax* variants; the InPlace variant uses no scratch reg.
void emit_vflags_store(RawEmitter& e, VflagsStoreV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp);

/// Read the scrambled slot and load real RFLAGS into the CPU via popfq.
/// Clobbers rax (except InPlace).
void emit_vflags_popfq(RawEmitter& e, VflagsPopfqV variant,
                       uint32_t vflags_key, uint32_t vflags_rol,
                       int32_t rflags_disp);

/// In-slot FORWARD transform: raw RFLAGS in the slot → scrambled RFLAGS.
/// Used by the entry stub right after pushfq writes raw flags to the slot.
void emit_vflags_inslot_scramble(RawEmitter& e, VflagsInSlotV variant,
                                 uint32_t vflags_key, uint32_t vflags_rol,
                                 int32_t rflags_disp);

/// In-slot REVERSE transform: scrambled RFLAGS in the slot → raw RFLAGS.
/// Used by the exit stub just before the final popfq.
void emit_vflags_inslot_descramble(RawEmitter& e, VflagsInSlotV variant,
                                   uint32_t vflags_key, uint32_t vflags_rol,
                                   int32_t rflags_disp);

/// Read scrambled slot, descramble, leave the result in ecx (used by VJCC
/// for bit testing). Clobbers ecx only.
void emit_vflags_to_ecx(RawEmitter& e, VflagsToEcxV variant,
                        uint32_t vflags_key, uint32_t vflags_rol,
                        int32_t rflags_disp);

} // namespace mx::vm::x64
