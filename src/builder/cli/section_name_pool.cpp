/**
 * @file section_name_pool.cpp
 * @brief Stealth section-name pools — implementation.
 *
 * See `section_name_pool.hpp` for the two-pool design and the
 * rationale for the per-kind dispatch. This file only carries the
 * actual pool contents and the Fisher–Yates sampler.
 */

#include "cli/section_name_pool.hpp"

#include <algorithm>
#include <cstdint>

namespace mx {

namespace {

/**
 * @brief User-mode stealth pool.
 *
 * Names common in MSVC / clang user-mode PE output:
 *   * `.rdata2` / `.rdata3`  — alternate read-only data.
 *   * `.xdata2` / `.xdata3`  — alternate x64 exception scope tables.
 *   * `.tls1` / `.tls2`      — per-module TLS overflow.
 *   * `.CRT$XC`              — CRT C++ initialiser fragment.
 *   * `.00cfg`               — Control Flow Guard bitmap header.
 *   * `.jcr`                 — legacy Java native registration.
 *   * `.gfids`               — CFG function-IDs table.
 *   * `.didat`               — delay-load import data.
 *   * `.edata1`              — alternate export data.
 *   * `.ptab`                — pointer probe table.
 *   * `.seh`                 — legacy SEH handler table.
 *   * `.tbase`               — thread-base scratch.
 *   * `.bss2`                — alternate zero-init data.
 *   * `.xtors` / `.ctors` / `.dtors` — GNU-toolchain constructors.
 *   * `.orpc`                — DCOM ORPC data.
 *
 * Every entry is ≤ 8 ASCII bytes and starts with `.`.
 */
const std::vector<std::string>& user_mode_pool() {
    static const std::vector<std::string> kPool = {
        ".rdata2", ".rdata3", ".xdata2", ".xdata3",
        ".tls1",   ".tls2",   ".CRT$XC", ".00cfg",
        ".jcr",    ".gfids",  ".didat",  ".edata1",
        ".ptab",   ".seh",    ".tbase",  ".bss2",
        ".xtors",  ".ctors",  ".dtors",  ".orpc",
    };
    return kPool;
}

/**
 * @brief Kernel-driver stealth pool.
 *
 * Names observed in real Windows kernel images (ntoskrnl, hal,
 * ntfs, cdfs, and common filesystem / device drivers). Using
 * user-mode section names in a `.sys` stands out immediately in
 * a kernel debugger's module list — these blend in.
 *
 *   * `PAGEBGFX`  — pageable boot-graphics code       (ntoskrnl)
 *   * `PAGEVRFY`  — pageable driver-verifier code     (ntoskrnl)
 *   * `PAGEKD`    — pageable kernel-debugger code     (ntoskrnl)
 *   * `PAGELK`    — pageable lock-enforced code       (ntoskrnl)
 *   * `PAGEDATA`  — pageable writable data            (generic)
 *   * `PAGECONS`  — pageable constant data            (fs drivers)
 *   * `PAGEXLAT`  — pageable translation tables       (fs drivers)
 *   * `NONPAGED`  — non-pageable data region          (generic)
 *   * `CACHEALI`  — cache-line-aligned data           (storage)
 *   * `INITDATA`  — INIT-lifetime writable data       (generic)
 *   * `KDDATA`    — kernel-debugger scratch           (ntoskrnl)
 *   * `ALMOSTRO`  — almost-read-only data             (ntoskrnl)
 *   * `ERRATA`    — CPU errata workarounds            (ntoskrnl)
 *   * `CDEXEC`    — CD-boot executable                (ntoskrnl)
 *   * `RWEXEC`    — read/write executable             (ntoskrnl)
 *   * `MINIEX`    — minimal executive                 (ntoskrnl)
 *
 * Every entry is ≤ 8 ASCII bytes and starts with an uppercase
 * letter — matching the kernel-image naming convention (as
 * opposed to the leading `.` that user-mode compilers prefer).
 *
 * Intentionally omitted: the base forms `INIT`, `PAGE`,
 * `NONPAGE`. Those ship in nearly every driver by default, so
 * picking them for our injected section would collide with the
 * input. Variant names (`INITDATA`, `PAGEDATA`, `NONPAGED`)
 * preserve the kernel-driver flavour without the collision risk.
 */
const std::vector<std::string>& driver_pool() {
    static const std::vector<std::string> kPool = {
        "PAGEBGFX", "PAGEVRFY", "PAGEKD",   "PAGELK",
        "PAGEDATA", "PAGECONS", "PAGEXLAT", "NONPAGED",
        "CACHEALI", "INITDATA", "KDDATA",   "ALMOSTRO",
        "ERRATA",   "CDEXEC",   "RWEXEC",   "MINIEX",
    };
    return kPool;
}

/**
 * @brief Draw the first `n` distinct entries from a shuffled copy
 *        of `pool`. `n` must be ≤ `pool.size()`; the caller
 *        pre-checks this via the ≥5 pool invariant.
 */
std::vector<std::string> sample_n(std::vector<std::string> pool,
                                   size_t n,
                                   Randomizer& rng)
{
    // Fisher-Yates — in-place, uniform distribution over all
    // permutations. We only need the first `n`, so iterating down
    // to index 0 does more work than strictly needed, but the
    // pools are tiny (≤20 entries) and this keeps the sampling
    // identical to the previous inlined version — useful for
    // callers that compare seeded output across refactors.
    for (size_t i = pool.size() - 1; i > 0; --i) {
        const uint32_t j = rng.next_range(0, static_cast<uint32_t>(i));
        std::swap(pool[i], pool[j]);
    }
    pool.resize(n);
    return pool;
}

} // anonymous namespace

const std::vector<std::string>& stealth_section_pool_for(
    target::BinaryKind kind)
{
    switch (kind) {
        case target::BinaryKind::executable:
        case target::BinaryKind::dynamic_library:
            return user_mode_pool();
        case target::BinaryKind::kernel_driver:
        case target::BinaryKind::efi_application:
            // EFI binaries share the driver-style stealth pool: like
            // .sys, they have no Win32-loader expectations on section
            // naming, and reusing the driver pool keeps `.mxpack` /
            // `.mxguard` style names out of UEFI builds. A dedicated
            // EFI pool can be split out later if the inspectors used
            // for UEFI start to flag these specific names.
            return driver_pool();
        case target::BinaryKind::unknown:
            break;
    }
    // Safety net — should never fire in practice: the caller
    // resolves `kind` from the PE parser which maps every
    // supported `PeType` to a concrete `BinaryKind`.
    return user_mode_pool();
}

SectionNameMap pick_section_names(target::BinaryKind kind,
                                   bool              debug_section_names,
                                   Randomizer&       rng)
{
    if (debug_section_names) {
        // `--debug-sections`: predictable names so the author
        // can grep + breakpoint by section name during pipeline
        // development. The fixed set intentionally ignores
        // `kind` — a driver build with `--debug-sections` still
        // gets `.mxpack`, because that is what the developer
        // expects to see in the build log.
        return SectionNameMap{
            .vm     = ".mxvm",
            .cff    = ".mxprot1",
            .packer = ".mxpack",
            .str    = ".mxstr",
            .guard  = ".mxguard",
            .mut    = ".mxmut",
        };
    }

    // Draw six distinct names from the kind-specific pool.
    auto draws = sample_n(stealth_section_pool_for(kind),
                          /*n=*/6, rng);

    return SectionNameMap{
        .vm     = std::move(draws[0]),
        .cff    = std::move(draws[1]),
        .packer = std::move(draws[2]),
        .str    = std::move(draws[3]),
        .guard  = std::move(draws[4]),
        .mut    = std::move(draws[5]),
    };
}

} // namespace mx
