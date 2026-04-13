/**
 * @file vm_stack_layout.hpp
 * @brief [BUILDER] Per-build VM stack layout descriptor (G7 randomization).
 *
 * Every virtualized region produces one `VmStackLayout` instance that
 * captures all per-build randomization of the VM context frame:
 *
 *   * Which virtual slot (0..15) hosts each native GPR — "dynamic register
 *     ordering". The lifter emits operands in native-reg space; the runtime
 *     generator remaps them to slot indices via this layout at encode time.
 *
 *   * Which slot is the junk / rolling-key host. Native RSP cannot be
 *     pushed, so its "would-be" slot becomes the junk slot. The rolling
 *     key seed is stored at `[rsp + junk_slot * 8]`.
 *
 *   * How many extra padding qwords sit between the GPR area and the
 *     RFLAGS slot ("G7 extra-pad slots"). Padding scales `rflags_offset`,
 *     `context_size`, and `native_frame_shift` per-build, so two builds
 *     of the same input produce different VM frame sizes and different
 *     entry/exit byte patterns.
 *
 * The padding sits ABOVE the GPR area. GPR slot offsets `[rsp + slot*8]`
 * with `slot ∈ [0..15]` are kept fixed across builds — every handler body
 * indexes them with disp8 SIB forms. Padding only changes RFLAGS-relative
 * disps, the native handler frame shift, and the entry/exit stub byte
 * sequences. Handler bodies stay byte-for-byte identical regardless of
 * padding count, which keeps the change cheap and risk-free.
 *
 * Lives in a public header so unit tests can verify layout invariants
 * without pulling in the entire VM runtime generator.
 */

#pragma once

#include <array>
#include <cstdint>

#include "mxprotector/core/randomizer.hpp"

namespace mx::vm {

/// Per-build randomized VM stack layout. POD-like: holds only data and
/// constexpr accessors. Constructed by `make_random` from a `Randomizer`.
struct VmStackLayout {
    /// Number of GPR / junk slots. Native x64 has 16 GPRs (RAX..R15),
    /// one of which (RSP) is never pushed; the slot that would hold it
    /// becomes the junk slot.
    static constexpr uint8_t kSlotCount = 16;

    /// Maximum extra padding qwords between the GPR area and the
    /// RFLAGS slot. Per-build random in [0, kMaxExtraPadSlots]. Each
    /// extra slot adds 8 bytes to context_size and to the native
    /// handler frame shift.
    ///
    /// Bound rationale: the entry stub pushes one `push imm32` per
    /// padding slot (5 bytes each), and the exit stub adds one
    /// `add rsp, imm8` cleanup. With max=7 the entry stub gains at
    /// most 35 bytes and the exit stub gains 4 bytes — small enough
    /// that even regions with many sub-VMs stay compact.
    static constexpr uint8_t kMaxExtraPadSlots = 7;

    /// Baseline (extra_pad_slots == 0) frame constants. Match the
    /// pre-G7 layout exactly so a layout with `extra_pad_slots == 0`
    /// produces byte-identical output to the legacy generator.
    static constexpr int32_t kBaseRflagsOffset = 128; ///< 16 slots * 8 bytes
    static constexpr int32_t kBaseContextSize  = 136; ///< GPR area + RFLAGS qword
    static constexpr int32_t kBaseNativeShift  = 168; ///< context + scratch + ret

    /// `slot_to_native[v]` = native GPR id stored at virtual slot v,
    /// or `kJunkMarker` if v is the junk slot. Exactly one entry equals
    /// `kJunkMarker`, and that index equals `junk_slot`.
    std::array<uint8_t, kSlotCount> slot_to_native{};

    /// `native_to_slot[n]` = the virtual slot holding native GPR n,
    /// or `kJunkMarker` for n == 4 (RSP — never pushed).
    std::array<uint8_t, kSlotCount> native_to_slot{};

    /// The slot that does NOT hold a real native reg. Hosts the rolling
    /// key scratch byte at its low byte; the upper 4 bytes are reused
    /// by the imagebase-key path to store the handler-table XOR key.
    uint8_t junk_slot = 0;

    /// Convenience: rolling key disp from rsp == junk_slot * 8.
    /// Always ≤ 120 → fits in disp8 forms.
    int32_t rolling_key_disp = 0;

    /// Number of extra 8-byte padding slots inserted between the GPR
    /// area and RFLAGS. Range: [0, kMaxExtraPadSlots].
    uint8_t extra_pad_slots = 0;

    /// Sentinel for `slot_to_native` / `native_to_slot` to mark the
    /// junk slot / RSP.
    static constexpr uint8_t kJunkMarker = 0xFF;

    /// Total size of the padding area in bytes.
    [[nodiscard]] constexpr int32_t pad_area_size() const noexcept {
        return static_cast<int32_t>(extra_pad_slots) * 8;
    }

    /// Disp from `rsp` (at handler entry) to the RFLAGS slot.
    [[nodiscard]] constexpr int32_t rflags_offset() const noexcept {
        return kBaseRflagsOffset + pad_area_size();
    }

    /// Total size of the VM context (GPR area + padding + RFLAGS qword).
    /// Does NOT include the call-site return address (which sits at
    /// `[rsp + context_size()]`).
    [[nodiscard]] constexpr int32_t context_size() const noexcept {
        return kBaseContextSize + pad_area_size();
    }

    /// Frame shift used by the native handler to reach the caller's rsp
    /// from `rsp_native = rsp_handler_entry - 24`.
    ///
    ///   shift = caller_rsp - rsp_native
    ///         = (rsp_handler_entry + context_size + 8 ret) - (rsp_handler_entry - 24)
    ///         = context_size + 8 + 24
    ///         = 168 + pad_area_size
    [[nodiscard]] constexpr int32_t native_frame_shift() const noexcept {
        return kBaseNativeShift + pad_area_size();
    }

    /// Build a fresh randomized layout from `rng`.
    [[nodiscard]] static VmStackLayout make_random(Randomizer& rng);
};

} // namespace mx::vm
