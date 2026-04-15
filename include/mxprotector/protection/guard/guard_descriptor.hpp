/**
 * @file guard_descriptor.hpp
 * @brief Data types shared across the runtime-guards subsystem.
 *
 * The runtime-guards milestone relocates code between `MX_GUARD_BEGIN`
 * and `MX_GUARD_END` onto its own 4 KB-aligned page inside a dedicated
 * `.mxguard` section. Each guard carries a small descriptor record that
 * ties the original source-side region to the relocated on-page body.
 * The descriptor is filled incrementally by `GuardPass` and then handed
 * over to later commits (VEH dispatcher, in-place page encryption, etc.)
 * via the context.
 *
 * Commit 2 scope: `GuardPass` only consumes the `source_*` fields and
 * produces the `page_*` fields. The later commits will extend the
 * descriptor with encryption-state flags, VEH lookup metadata, and
 * thread-open counters — all additive fields that keep the existing
 * layout stable.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::guard {

/// Fixed page granularity used by the runtime-guards subsystem. All
/// guard bodies are relocated onto pages of exactly this size, and the
/// `.mxguard` section is aligned so that each descriptor's `page_rva`
/// lands on a `kGuardPageSize` boundary. The value matches the Windows
/// x64 user-mode page size so later commits can hand whole pages to
/// `NtProtectVirtualMemory` without sub-page partial writes.
inline constexpr uint32_t kGuardPageSize = 4096;

/**
 * @brief Full record for one `MX_GUARD_BEGIN`/`MX_GUARD_END` region.
 *
 * Populated by `GuardPass`. Every RVA is measured in the protected
 * image's virtual-address space.
 *
 * ### Source-side fields
 * The `source_*` fields describe the original byte range that the
 * SDK markers enclosed in the input image:
 *
 *   * `source_begin_marker_rva` — start of the `MX_GUARD_BEGIN`
 *     marker instruction (the `48 B8 imm64` emitted by the SDK).
 *   * `source_body_start_rva`   — first byte of the user's body
 *     (`source_begin_marker_rva + begin_marker_size`).
 *   * `source_body_end_rva`     — one past the last byte of the
 *     user's body (= the start of the `MX_GUARD_END` marker).
 *   * `source_total_patch_size` — total byte count that `GuardPass`
 *     overwrites in the source section with the `jmp rel32 <page>`
 *     + NOP padding (`begin_marker_size + body_size + end_marker_size`).
 *   * `source_section_index`    — index of the source `.text`-like
 *     section inside `pe_image.sections()`.
 *   * `return_rva`              — address control flow must return
 *     to after the guard body finishes executing (= the first byte
 *     past the `MX_GUARD_END` marker). The relocated body's exit
 *     trampoline jumps here in Commit 2; Commit 3's exit VEH will
 *     read this from the descriptor and set `CONTEXT.Rip` directly.
 *
 * ### Page-side fields
 * The `page_*` fields describe the relocated body as it lives inside
 * the `.mxguard` section:
 *
 *   * `guard_id`      — 0-based, stable build-time identifier that
 *     Commit 3's entry/exit `int3 + tag` markers encode into their
 *     trailing 4-byte tag.
 *   * `page_rva`      — runtime RVA of the guard's page (inside the
 *     protected image). Multiple of `kGuardPageSize`.
 *   * `body_offset`   — offset inside the page where the body bytes
 *     begin. In Commit 2 this is `0`; Commit 3 bumps it to `5` to
 *     leave room for the entry `int3 + tag` plaintext window.
 *   * `body_size`     — number of body bytes copied from the source.
 *     Equals `source_body_end_rva - source_body_start_rva`, minus
 *     any rejected trailing bytes (none in Commit 2).
 */
struct GuardDescriptor {
    // --- Source side --------------------------------------------------
    uint32_t source_section_index  = 0;
    Rva      source_begin_marker_rva = 0;
    Rva      source_body_start_rva = 0;
    Rva      source_body_end_rva   = 0;
    uint32_t source_total_patch_size = 0;
    Rva      return_rva            = 0;

    // --- Page side ----------------------------------------------------
    uint32_t guard_id    = 0;
    Rva      page_rva    = 0;
    uint32_t body_offset = 0;
    uint32_t body_size   = 0;
};

} // namespace mx::guard
