/**
 * @file arch_info.hpp
 * @brief Fine-grained architecture descriptor (variant + features).
 *
 * `mx::target::Arch` (see `mxprotector/target/target_info.hpp`) identifies the
 * architecture *family* — x64, arm64, cortex-m — and is what cross-cutting
 * pipeline decisions use ("is this a PE x64 build?"). That's deliberately
 * coarse because most passes don't care about micro-architecture differences.
 *
 * This file layers detail on top for the passes that DO care — specifically
 * the architecture backends (code emitter, VM backend, mutation rules). An
 * `ArchInfo` captures:
 *
 *   - family (x64, x86, arm64, cortex_m, …)
 *   - variant inside the family (armv8.0-a, armv8.1-a, Cortex-M4, …)
 *   - profile (Application / Realtime / Microcontroller for ARM)
 *   - optional feature bits (NEON, crypto ext, atomic, MTE, BTI, …)
 *
 * How it plugs in
 * ---------------
 * - `target::TargetInfo` stays the high-level seam (OS × container × family).
 * - `arch::ArchInfo` sits inside the arch backend's private state and is
 *   selected by the backend factory from the `target::TargetInfo` passed in.
 * - A pass that only needs "is this x64?" keeps reading `ctx.target().arch`.
 * - A pass that needs "does this target have NEON?" reads the `ArchInfo` on
 *   the backend it's talking to.
 *
 * This file is part of the Phase 5 foundation — it declares types and
 * factory helpers but does not drive codegen today. The x64 pipeline still
 * emits bytes directly in `vm_runtime_gen.cpp`; when the arm64 backend gets
 * implemented, both backends start consuming `ArchInfo` in their
 * constructors.
 */

#pragma once

#include <cstdint>

#include "mxprotector/target/target_info.hpp"

namespace mx::arch {

/// Architecture family. Thin alias over `target::Arch` for readability at
/// the backend boundary; the values are identical so the two can be
/// compared directly.
using ArchFamily = target::Arch;

/**
 * @brief Profile of an ARM architecture variant.
 *
 * ARMv7 onwards distinguishes three profiles:
 *   - `application`: Cortex-A cores, MMU, full OS support (embedded Linux,
 *     Android, server, desktop).
 *   - `realtime`:   Cortex-R cores, no MMU, hard-real-time (networking,
 *     storage controllers). Not a priority target.
 *   - `microcontroller`: Cortex-M cores, Thumb-only, no A64, bare-metal or
 *     RTOS (FreeRTOS, Zephyr). Future / experimental target.
 *
 * For non-ARM targets this is `generic`.
 */
enum class ArchProfile : uint8_t {
    generic         = 0,   ///< x86/x64 or "don't care"
    application     = 1,   ///< Cortex-A (has MMU, full OS)
    realtime        = 2,   ///< Cortex-R (no MMU)
    microcontroller = 3,   ///< Cortex-M (Thumb-only, bare-metal)
};

/**
 * @brief Named variant inside an architecture family.
 *
 * These map onto the `-march=` / LLVM target-triple vendor strings so users
 * of the builder can spell them the way their toolchain already does.
 */
enum class ArchVariant : uint8_t {
    // --- x86 family ---
    x64_generic    = 0,   ///< "x86_64" — any Intel/AMD 64-bit CPU since Nehalem
    x86_i686       = 1,   ///< 32-bit x86, Pentium Pro and up

    // --- ARM64 family ---
    arm64_v8a      = 10,  ///< ARMv8.0-A — baseline 64-bit ARM (RPi 3, first Apple Silicon)
    arm64_v8_1a    = 11,  ///< + LSE atomics, CRC32, VFP extended
    arm64_v8_2a    = 12,  ///< + half-float, crypto, RAS, cache maintenance
    arm64_v8_3a    = 13,  ///< + PAC (pointer authentication), JS conversions
    arm64_v8_4a    = 14,  ///< + dot product, TLBI by range
    arm64_v8_5a    = 15,  ///< + MTE (memory tagging), BTI (branch target id)
    arm64_v9_0a    = 16,  ///< ARMv9.0-A — SVE2 baseline

    // --- ARM Cortex-M (Thumb/Thumb-2 only) ---
    cortex_m0      = 20,  ///< ARMv6-M — minimal core, no Thumb-2 (STM32F0, nRF51)
    cortex_m3      = 21,  ///< ARMv7-M — Thumb-2, no FPU (STM32F1)
    cortex_m4      = 22,  ///< ARMv7E-M — + DSP, optional FPU (STM32F4)
    cortex_m7      = 23,  ///< ARMv7E-M — superscalar, double-precision FPU (STM32F7/H7)
    cortex_m33     = 24,  ///< ARMv8-M — TrustZone-M (Nordic nRF91)

    // --- ARM Cortex-R (real-time) — listed for completeness, not a near-term target ---
    cortex_r5      = 30,
    cortex_r52     = 31,

    unknown        = 0xFF,
};

/**
 * @brief Optional feature bits a backend can query for codegen decisions.
 *
 * On x64 NEON and crypto are always meaningful (SSE / AES-NI / SHA-NI). On
 * arm64 they are the ARMv8 equivalents. On Cortex-M most of these are
 * absent — the backend can fall back to plain integer sequences.
 *
 * These are treated as a bitset so a single struct can describe both x64
 * and arm64 capabilities without branching on family first.
 */
struct ArchFeatures {
    // Vector / crypto
    bool has_simd_128     = false;  ///< x64: SSE2; arm64: NEON
    bool has_simd_256     = false;  ///< x64: AVX2
    bool has_simd_512     = false;  ///< x64: AVX-512
    bool has_crypto_aes   = false;  ///< x64: AES-NI; arm64: FEAT_AES
    bool has_crypto_sha   = false;  ///< x64: SHA-NI; arm64: FEAT_SHA2
    bool has_crypto_pmull = false;  ///< x64: PCLMULQDQ; arm64: FEAT_PMULL

    // Integer / memory
    bool has_lse_atomics  = false;  ///< arm64 only (FEAT_LSE, ARMv8.1-A+)
    bool has_bti          = false;  ///< arm64 only (FEAT_BTI, ARMv8.5-A+)
    bool has_pac          = false;  ///< arm64 only (FEAT_PAuth, ARMv8.3-A+)
    bool has_mte          = false;  ///< arm64 only (FEAT_MTE, ARMv8.5-A+)

    // Floating point
    bool has_fpu          = true;   ///< false on Cortex-M0/M3 without FPU
    bool has_fp16         = false;  ///< arm64: FEAT_FP16; x64: F16C

    // Profiling / timing
    bool has_rdtsc        = false;  ///< x64 only (RDTSC)
    bool has_cntvct       = false;  ///< arm64 only (CNTVCT_EL0 cycle counter)
};

/**
 * @brief Full architecture descriptor. Passed to backend constructors.
 *
 * This is the value every arch backend (x64 VM runtime gen, future arm64
 * VM runtime gen, mutation rules, code emitter) reads at construction time
 * to pick instruction forms, register widths, and available features.
 *
 * The `family` field is redundant with `variant` for correctness (variant
 * already implies family), but having both lets callers do fast family
 * checks without decoding the variant.
 */
struct ArchInfo {
    ArchFamily   family  = ArchFamily::unknown;
    ArchVariant  variant = ArchVariant::unknown;
    ArchProfile  profile = ArchProfile::generic;
    ArchFeatures features{};

    // ------------------------------------------------------------------------
    // Factory helpers — prefer these over poking fields directly.
    // ------------------------------------------------------------------------

    /// Generic x86_64 baseline (Nehalem and up): SSE2 available, no AVX.
    [[nodiscard]] static ArchInfo x64_baseline() noexcept {
        ArchInfo info;
        info.family  = ArchFamily::x64;
        info.variant = ArchVariant::x64_generic;
        info.profile = ArchProfile::generic;
        info.features.has_simd_128 = true;
        info.features.has_fpu      = true;
        info.features.has_rdtsc    = true;
        return info;
    }

    /// x86_64 with modern extensions (Haswell+).
    [[nodiscard]] static ArchInfo x64_modern() noexcept {
        ArchInfo info = x64_baseline();
        info.features.has_simd_256     = true;
        info.features.has_crypto_aes   = true;  // AES-NI
        info.features.has_crypto_pmull = true;  // PCLMULQDQ
        return info;
    }

    /// ARMv8.0-A baseline (Cortex-A53, RPi 3, first-gen Apple Silicon) — the
    /// lowest common denominator for all 64-bit ARM application targets.
    [[nodiscard]] static ArchInfo arm64_v8a_application() noexcept {
        ArchInfo info;
        info.family  = ArchFamily::arm64;
        info.variant = ArchVariant::arm64_v8a;
        info.profile = ArchProfile::application;
        info.features.has_simd_128 = true;  // NEON is mandatory in v8a
        info.features.has_fpu      = true;  // mandatory in v8a
        info.features.has_cntvct   = true;
        return info;
    }

    /// ARMv8.2-A with crypto — typical Android smartphone / mid-range SBC.
    [[nodiscard]] static ArchInfo arm64_v82a_crypto() noexcept {
        ArchInfo info = arm64_v8a_application();
        info.variant = ArchVariant::arm64_v8_2a;
        info.features.has_crypto_aes   = true;
        info.features.has_crypto_sha   = true;
        info.features.has_crypto_pmull = true;
        info.features.has_lse_atomics  = true;
        info.features.has_fp16         = true;
        return info;
    }

    /// Cortex-M4 — typical STM32 target, DSP, optional single-precision FPU.
    /// Listed for completeness; Cortex-M is not a near-term target.
    [[nodiscard]] static ArchInfo cortex_m4() noexcept {
        ArchInfo info;
        info.family  = ArchFamily::arm64;  // closest match in coarse family
        info.variant = ArchVariant::cortex_m4;
        info.profile = ArchProfile::microcontroller;
        info.features.has_fpu = true;
        return info;
    }

    // ------------------------------------------------------------------------
    // Predicates
    // ------------------------------------------------------------------------

    [[nodiscard]] constexpr bool is_x86_family() const noexcept {
        return family == ArchFamily::x64 || family == ArchFamily::x86;
    }
    [[nodiscard]] constexpr bool is_arm_family() const noexcept {
        return family == ArchFamily::arm64;
    }
    [[nodiscard]] constexpr bool is_64bit() const noexcept {
        return family == ArchFamily::x64 || family == ArchFamily::arm64;
    }
    [[nodiscard]] constexpr bool is_microcontroller() const noexcept {
        return profile == ArchProfile::microcontroller;
    }
    [[nodiscard]] constexpr bool is_application_class() const noexcept {
        return profile == ArchProfile::application || is_x86_family();
    }
};

/// Human-readable name of the variant, for logs / CLI output.
[[nodiscard]] constexpr const char* variant_name(ArchVariant v) noexcept {
    switch (v) {
        case ArchVariant::x64_generic:  return "x86_64";
        case ArchVariant::x86_i686:     return "i686";
        case ArchVariant::arm64_v8a:    return "armv8-a";
        case ArchVariant::arm64_v8_1a:  return "armv8.1-a";
        case ArchVariant::arm64_v8_2a:  return "armv8.2-a";
        case ArchVariant::arm64_v8_3a:  return "armv8.3-a";
        case ArchVariant::arm64_v8_4a:  return "armv8.4-a";
        case ArchVariant::arm64_v8_5a:  return "armv8.5-a";
        case ArchVariant::arm64_v9_0a:  return "armv9-a";
        case ArchVariant::cortex_m0:    return "cortex-m0";
        case ArchVariant::cortex_m3:    return "cortex-m3";
        case ArchVariant::cortex_m4:    return "cortex-m4";
        case ArchVariant::cortex_m7:    return "cortex-m7";
        case ArchVariant::cortex_m33:   return "cortex-m33";
        case ArchVariant::cortex_r5:    return "cortex-r5";
        case ArchVariant::cortex_r52:   return "cortex-r52";
        case ArchVariant::unknown:      return "unknown";
    }
    return "?";
}

} // namespace mx::arch
