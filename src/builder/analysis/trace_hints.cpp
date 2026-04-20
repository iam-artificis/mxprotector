/**
 * @file trace_hints.cpp
 * @brief [BUILDER] TraceHints — mutation API + enum-to-string helpers.
 *
 * @details Разделён с `trace_hints_serialize.cpp` на два TU чтобы
 *          каждый файл оставался под 300-LOC лимитом. Этот файл
 *          содержит только простые setter'ы/adder'ы + enum→string.
 *          Сама `to_json()` и per-section JSON-writer'ы живут в
 *          `trace_hints_serialize.cpp`.
 */

#include "mxprotector/analysis/trace_hints.hpp"

namespace mx::analysis {

// ============================================================================
// enum → JSON-string
// ============================================================================

std::string_view cff_state_kind_name(CffStateKind k) noexcept {
    switch (k) {
        case CffStateKind::original:  return "original";
        case CffStateKind::predicate: return "predicate";
        case CffStateKind::mba:       return "mba";
        case CffStateKind::bogus:     return "bogus";
    }
    return "unknown";
}

std::string_view predicate_kind_name(PredicateKind k) noexcept {
    switch (k) {
        case PredicateKind::opaque_hash:    return "opaque_hash";
        case PredicateKind::mba_transition: return "mba_transition";
    }
    return "unknown";
}

// ============================================================================
// Phase 1 — build info + sections
// ============================================================================

void TraceHints::set_build_info(std::string_view input,
                                std::string_view output,
                                std::string_view level,
                                std::string_view timestamp)
{
    build_.input     = input;
    build_.output    = output;
    build_.level     = level;
    build_.timestamp = timestamp;
}

void TraceHints::add_section(std::string_view role,
                             std::string_view name,
                             std::uint32_t    rva,
                             std::uint32_t    size,
                             std::uint32_t    characteristics)
{
    sections_.push_back(TraceHintsSection{
        .role            = std::string(role),
        .name            = std::string(name),
        .rva             = rva,
        .size            = size,
        .characteristics = characteristics,
    });
}

// ============================================================================
// Phase 4A — CFF / VM / Guard / Strings / IAT
// ============================================================================

void TraceHints::set_cff_dispatcher(std::uint32_t dispatcher_rva,
                                    std::uint32_t state_var_rva) noexcept
{
    cff_.dispatcher_rva = dispatcher_rva;
    cff_.state_var_rva  = state_var_rva;
}

void TraceHints::add_cff_state(std::uint32_t id,
                               std::uint32_t dispatcher_entry_rva,
                               std::uint32_t source_bb_rva,
                               CffStateKind  kind)
{
    cff_.states.push_back(CffStateLabel{
        .id                   = id,
        .dispatcher_entry_rva = dispatcher_entry_rva,
        .source_bb_rva        = source_bb_rva,
        .kind                 = kind,
    });
}

void TraceHints::add_opaque_predicate(std::uint32_t id,
                                      std::uint32_t rva,
                                      PredicateKind kind)
{
    cff_.predicates.push_back(CffPredicateLabel{
        .id = id, .rva = rva, .kind = kind,
    });
}

void TraceHints::set_vm_dispatcher(std::uint32_t dispatcher_rva,
                                   std::uint32_t handler_table_rva) noexcept
{
    vm_.dispatcher_rva    = dispatcher_rva;
    vm_.handler_table_rva = handler_table_rva;
}

void TraceHints::add_vm_handler(std::uint32_t    id,
                                std::uint32_t    rva,
                                std::uint32_t    size,
                                std::string_view opcode)
{
    vm_.handlers.push_back(VmHandlerLabel{
        .id     = id,
        .rva    = rva,
        .size   = size,
        .opcode = std::string(opcode),
    });
}

void TraceHints::add_guard_region(std::uint32_t id,
                                  std::uint32_t rva,
                                  std::uint32_t size)
{
    guard_.regions.push_back(GuardRegionLabel{
        .id = id, .rva = rva, .size = size,
    });
}

void TraceHints::add_string_slot(std::uint32_t id,
                                 std::uint32_t desc_rva,
                                 std::uint32_t plaintext_len)
{
    strings_.slots.push_back(StringSlotLabel{
        .id            = id,
        .desc_rva      = desc_rva,
        .plaintext_len = plaintext_len,
    });
}

void TraceHints::set_iat(std::uint32_t rva, std::uint32_t size) noexcept {
    iat_.rva  = rva;
    iat_.size = size;
}

// ============================================================================
// Query
// ============================================================================

bool TraceHints::empty() const noexcept {
    return build_.input.empty()
        && build_.output.empty()
        && build_.level.empty()
        && build_.timestamp.empty()
        && sections_.empty()
        && cff_.dispatcher_rva == 0
        && cff_.state_var_rva  == 0
        && cff_.states.empty()
        && cff_.predicates.empty()
        && vm_.dispatcher_rva    == 0
        && vm_.handler_table_rva == 0
        && vm_.handlers.empty()
        && guard_.regions.empty()
        && strings_.slots.empty()
        && iat_.rva  == 0
        && iat_.size == 0;
}

} // namespace mx::analysis
