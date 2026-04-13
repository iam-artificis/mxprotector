/**
 * @file vm_stack_layout.cpp
 * @brief [BUILDER] VmStackLayout::make_random implementation.
 *
 * The previous in-place `make_random_layout` lambda inside vm_runtime_gen.cpp
 * built the GPR permutation. This file keeps the same algorithm verbatim
 * (Fisher–Yates of 16 slots, RSP's would-be slot becomes the junk slot)
 * and additionally picks an `extra_pad_slots` count for G7.
 */

#include "mxprotector/protection/vm/vm_stack_layout.hpp"

#include <algorithm>
#include <numeric>

namespace mx::vm {

VmStackLayout VmStackLayout::make_random(Randomizer& rng) {
    VmStackLayout L{};

    // Identity permutation of 16 slots, then Fisher–Yates shuffle.
    std::array<uint8_t, kSlotCount> perm{};
    std::iota(perm.begin(), perm.end(), static_cast<uint8_t>(0));
    for (size_t i = kSlotCount - 1; i > 0; --i) {
        const uint32_t j = rng.next_range(0, static_cast<uint32_t>(i));
        std::swap(perm[i], perm[j]);
    }

    // perm[v] == native reg stored at slot v.
    L.slot_to_native = perm;
    L.native_to_slot.fill(kJunkMarker);
    for (uint8_t v = 0; v < kSlotCount; ++v) {
        L.native_to_slot[perm[v]] = v;
    }

    // Native 4 = RSP cannot be pushed; its slot becomes the junk slot.
    L.junk_slot = L.native_to_slot[4];
    L.slot_to_native[L.junk_slot] = kJunkMarker;
    L.native_to_slot[4] = kJunkMarker;
    L.rolling_key_disp = static_cast<int32_t>(L.junk_slot) * 8;

    // G7: pick a uniform random number of extra padding slots in
    // [0, kMaxExtraPadSlots]. A draw of 0 reproduces the legacy layout
    // exactly, so the worst case is "no variance for this build" — never
    // a regression. Higher draws expand the frame above the GPR area.
    L.extra_pad_slots = static_cast<uint8_t>(
        rng.next_range(0, static_cast<uint32_t>(kMaxExtraPadSlots)));

    return L;
}

} // namespace mx::vm
