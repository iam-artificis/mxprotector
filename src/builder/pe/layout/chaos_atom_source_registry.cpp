/**
 * @file chaos_atom_source_registry.cpp
 * @brief Implementation — see header.
 */

#include "mxprotector/pe/layout/chaos_atom_source_registry.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/pe/chaos/basic_block_atom_source.hpp"
#include "mxprotector/pe/chaos/code_gap_pin_atom_source.hpp"
#include "mxprotector/pe/chaos/data_section_pin_atom_source.hpp"
#include "mxprotector/pe/chaos/delay_import_atom_source.hpp"
#include "mxprotector/pe/chaos/import_atom_source.hpp"
#include "mxprotector/pe/chaos/load_config_atom_source.hpp"
#include "mxprotector/pe/chaos/pdata_atom_source.hpp"
#include "mxprotector/pe/chaos/reloc_atom_source.hpp"
#include "mxprotector/pe/chaos/section_movable_block_atom_source.hpp"
#include "mxprotector/pe/chaos/tls_atom_source.hpp"
#include "mxprotector/pe/chaos/volatile_metadata_atom_source.hpp"

namespace mx::pe::chaos {

void register_atom_sources(AtomicChunkPlanner& planner) {
    using std::make_unique;

    // 1. Movable: per-sub-function atoms (B.4.23 + B.4.23.1).
    //    `BasicBlockAtomSource` walks `.pdata` with Zydis and emits
    //    one atom per run that ends with an unconditional terminator
    //    on a 4-aligned RVA. The planner refuses any split point
    //    that would put a `rel8`/`rel32` slot in one chunk and its
    //    target in another. Functions with no usable splits collapse
    //    to a single function-sized atom.
    planner.add_source(make_unique<BasicBlockAtomSource>());

    // 1a. Movable: per-section emitter-declared sub-blocks
    //     (`SectionInfo::movable_blocks`). Currently feeds the
    //     1296+ indirect-call stubs from `.callstub` into the
    //     planner; future passes (CFF block shuffle, MBA-noise
    //     blocks) drop in here without touching this file.
    planner.add_source(make_unique<SectionMovableBlockAtomSource>());

    // 2. Pinned: every byte in `.text` outside any `.pdata`-listed
    //    function. These are inter-function thunks and CFG stubs
    //    the loader and runtime can still call into; pinning them
    //    keeps their bytes verbatim at the original RVA.
    planner.add_source(make_unique<CodeGapPinAtomSource>());

    // 2. Pinned: every PE directory the loader walks linearly.
    planner.add_source(make_unique<ImportAtomSource>());
    planner.add_source(make_unique<DelayImportAtomSource>());
    planner.add_source(make_unique<TlsAtomSource>());
    planner.add_source(make_unique<PdataAtomSource>());
    planner.add_source(make_unique<LoadConfigAtomSource>());
    planner.add_source(make_unique<VolatileMetadataAtomSource>());
    planner.add_source(make_unique<RelocBlockAtomSource>());
    planner.add_source(make_unique<RelocPointerAtomSource>());

    // 3. Pinned: every byte in every non-code section. Prevents the
    //    loose-chunk carving from splitting natural-aligned values
    //    (`__security_cookie`, vtable slots, …) across chunks.
    planner.add_source(make_unique<DataSectionPinAtomSource>());
}

std::uint64_t fresh_seed() {
    if (const char* env = std::getenv("MX_CHAOS_SEED"); env != nullptr) {
        std::uint64_t parsed = 0;
        bool ok = true;
        for (const char* p = env; *p && ok; ++p) {
            parsed <<= 4;
            const char c = *p;
            if      (c >= '0' && c <= '9') parsed |= static_cast<std::uint64_t>(c - '0');
            else if (c >= 'a' && c <= 'f') parsed |= static_cast<std::uint64_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') parsed |= static_cast<std::uint64_t>(c - 'A' + 10);
            else { ok = false; }
        }
        if (ok) {
            std::fprintf(stderr,
                "[chaos] MX_CHAOS_SEED override: 0x%016llx\n",
                static_cast<unsigned long long>(parsed));
            return parsed;
        }
    }
    Randomizer rng;
    return rng.next_u64();
}

} // namespace mx::pe::chaos
