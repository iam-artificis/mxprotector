/**
 * @file state_reg_picker.hpp
 * @brief Pick a free GPR inside a function body for the CFF state variable.
 *
 * The CFG flattener stores the current block's state id in a register that
 * stays live across the dispatcher jumps. The register must not be touched
 * by the function's original body — if we picked, say, `rcx`, every `mov
 * rcx, ...` inside the function would corrupt the state and the dispatcher
 * would send control to a random block.
 *
 * We scan the candidate register set (currently `r10`, `r11` — both ABI
 * scratch and rarely used by MSVC prologues) against the function body via
 * Zydis and return the first one that's unused. If every candidate is in
 * use, `select_state_register` returns `std::nullopt` and the caller must
 * skip the function.
 */

#pragma once

#include <optional>

#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/core/types.hpp"

namespace mx::cff {

/**
 * @brief Return the first candidate GPR not referenced by `func_code`.
 *
 * @param func_code Raw bytes of the function body.
 * @return The chosen register, or `std::nullopt` if every candidate is in
 *         use by the function.
 */
[[nodiscard]] std::optional<x86::Reg>
select_state_register(ByteView func_code) noexcept;

} // namespace mx::cff
