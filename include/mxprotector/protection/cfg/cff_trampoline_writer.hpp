/**
 * @file cff_trampoline_writer.hpp
 * @brief Overwrite a function body with a 5-byte JMP to its relocated copy.
 *
 * When the flattened form of a function doesn't fit inside the original
 * byte range, the flattener moves it into a dedicated trampoline
 * section (`.mxprot1` or equivalent per-build name). The original range
 * is then repurposed as a single `jmp rel32` that hands control over to
 * the new location, followed by `0xCC` padding for any leftover bytes.
 *
 * Every decision about stealing / keeping / extending lives upstream;
 * this header is the one-line primitive that writes the JMP once all
 * the decisions have been made.
 */

#pragma once

#include <cstdint>

#include "mxprotector/core/types.hpp"

namespace mx::pe {
struct SectionInfo;
}

namespace mx::cff {

/**
 * @brief Write `jmp rel32` + `0xCC` padding into a section's bytes.
 *
 * @param section             Section whose bytes hold the original
 *                            function. Written in-place.
 * @param offset_in_section   Byte offset where the original function
 *                            starts inside `section.data`.
 * @param original_size       Size of the original function body. Must
 *                            be ≥ 5; leftover bytes after the 5-byte
 *                            JMP are filled with `0xCC`.
 * @param source_rva          RVA of the JMP instruction (usually the
 *                            function's original RVA).
 * @param target_rva          RVA the JMP redirects to (the relocated
 *                            flattened function).
 *
 * The function silently returns without writing anything when the
 * requested range extends past the section buffer. Callers are
 * expected to have validated both `original_size ≥ 5` and the range
 * bound before calling.
 */
void write_jmp_trampoline(pe::SectionInfo& section,
                          uint32_t         offset_in_section,
                          uint32_t         original_size,
                          Rva              source_rva,
                          Rva              target_rva) noexcept;

} // namespace mx::cff
