#pragma once

#include <cstdint>

#include "mxprotector/core/raw_emitter.hpp"

namespace mx::guard {

struct GuardDecryptUnitEmit {
    uint32_t size = 0;
};

inline constexpr uint32_t kGuardDecryptUnitSize = 54;

[[nodiscard]] GuardDecryptUnitEmit emit_guard_decrypt_unit(RawEmitter& e);

} // namespace mx::guard
