/**
 * @file vm_runtime_gen.hpp
 * @brief [BUILDER] Генератор VM runtime: entry stub, dispatcher, handlers, bytecode.
 *
 * На каждый виртуализованный регион генерируется независимый VM runtime
 * (entry + dispatcher + set of handlers + bytecode stream), который
 * складывается в секцию .mxvm. Все компоненты расположены в одном буфере:
 *
 *   [vm_entry_code] ... [dispatcher] ... [handlers] ... [bytecode_stream]
 *
 * Entry — точка, на которую заменяется оригинальная инструкция (JMP rel32
 * с последующим возвратом по RET). Entry сохраняет все регистры и RFLAGS
 * на стэк (формируя VM-контекст in-place), инициализирует vpc (R11),
 * переходит в dispatcher. Dispatcher декодирует опкод и прыгает в handler.
 * Каждый handler выполняет свою операцию над VM-контекстом в стэке и
 * возвращается в dispatcher. VmOp::exit восстанавливает регистры и делает ret.
 *
 * Per-build рандомизация:
 *  - handler-индексы перестанавливаются (VmOpcodeMap)
 *  - bytecode XOR-шифруется stream-ключом (opcode_xor_key)
 *  - порядок handlers в памяти перемешивается
 */

#pragma once

#include <cstdint>
#include <vector>

#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/types.hpp"
#include "mxprotector/protection/vm/vm_bytecode.hpp"

namespace mx::vm {

struct VmRuntime {
    ByteBuffer blob;                  ///< Полный runtime: entry + handlers + bytecode
    uint32_t   entry_offset = 0;      ///< Смещение entry point в blob
    uint32_t   bytecode_offset = 0;   ///< Смещение bytecode
    uint32_t   bytecode_size = 0;
    uint32_t   handler_count = 0;
    VmOpcodeMap opcode_map;

    /// If non-zero, the exit handler emits `jmp rel32` instead of `ret`.
    /// The rel32 at this offset must be patched to the next VM's entry.
    uint32_t   exit_jmp_patch = 0;
};

class VmRuntimeGenerator final {
public:
    /**
     * @brief Генерирует VM runtime для последовательности VM-инструкций.
     *
     * @param instructions    Результат лифтинга (без финального exit).
     * @param rng             Генератор для рандомизации маппинга/ключа.
     * @param emit_exit_as_jmp If true, the exit handler emits `jmp rel32`
     *        instead of `ret`. Used for Cross-VM sub-VMs.
     *
     * Each sub-VM independently picks its own (vflags_key, vflags_rol)
     * pair — no state needs to be shared across sub-VMs because the exit
     * stub fully descrambles RFLAGS before popfq and the entry stub
     * re-scrambles after pushfq.
     *
     * @return VmRuntime c байт-блобом, готовым к размещению в секции.
     */
    [[nodiscard]] MxResult<VmRuntime> generate(
        const std::vector<VmInstruction>& instructions,
        Randomizer& rng,
        bool emit_exit_as_jmp = false);

private:
    /**
     * @brief Шифрует байт bytecode stream key-ключом (XOR).
     */
    [[nodiscard]] static uint8_t encrypt_byte(uint8_t b, uint8_t key) noexcept {
        return static_cast<uint8_t>(b ^ key);
    }
};

} // namespace mx::vm
