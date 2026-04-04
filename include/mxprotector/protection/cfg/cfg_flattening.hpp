/**
 * @file cfg_flattening.hpp
 * @brief [BUILDER] Control Flow Flattening (CFF) — проход защиты пайплайна.
 *
 * @details CfgFlatteningPass реализует IProtectionPass и координирует полный
 *          процесс расплющивания потока управления:
 *
 *          1. Построение CFG функции (через CfgBuilder).
 *          2. Назначение случайных state_id каждому базовому блоку.
 *          3. Генерация dispatcher-блока (switch по state variable).
 *          4. Трансформация переходов: замена jmp/jcc на обновление state + jmp dispatcher.
 *          5. Вставка bogus flow (ложных путей) с opaque predicates.
 *          6. MBA-обфускация state transitions (опционально).
 *          7. Запись результата обратно в PE-образ.
 *
 *          CfgFlattener — вспомогательный класс, инкапсулирующий логику
 *          расплющивания одной функции. CfgFlatteningPass итерирует по
 *          маркированным регионам и вызывает CfgFlattener для каждого.
 *
 *          SOLID:
 *          - SRP: CfgFlatteningPass координирует, CfgFlattener трансформирует,
 *                 DispatcherGenerator генерирует dispatcher, BogusFlowGenerator
 *                 генерирует ложный поток.
 *          - OCP: новые стратегии диспетчеризации добавляются без изменения pass.
 *          - DIP: зависит от абстракций (IDisassembler, IProtectionPass).
 *
 * @note Приоритет: 400 (категория cfg_transform, после мутации/обфускации).
 *       Применяется к регионам MX_OBFUSCATE_BEGIN/END или ко всем кодовым секциям.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "mxprotector/core/types.hpp"
#include "mxprotector/core/result.hpp"
#include "mxprotector/core/randomizer.hpp"
#include "mxprotector/analysis/cfg.hpp"
#include "mxprotector/analysis/assembler.hpp"
#include "mxprotector/protection/pass.hpp"
#include "mxprotector/protection/cfg/dispatcher_gen.hpp"
#include "mxprotector/protection/cfg/bogus_flow.hpp"

namespace mx {

class ProtectionContext;

/**
 * @brief Конфигурация расплющивания для одной функции.
 */
struct FlatteningConfig {
    x86::Reg state_var_reg = x86::Reg::r10;
    bool     enable_bogus_flow = true;
    double   bogus_probability = 0.5;
    bool     enable_mba_transitions = true;
    uint32_t mba_depth = 1;
};

/**
 * @brief Результат расплющивания одной функции.
 */
struct FlatteningResult {
    ByteBuffer flattened_code;
    uint32_t   original_block_count = 0;
    uint32_t   total_block_count    = 0;
    uint32_t   bogus_blocks_added   = 0;
    uint32_t   total_size           = 0;
    std::vector<BlockPlacement> block_placements;
};

/**
 * @brief Запись для трамплин-перенаправления в новую секцию.
 */
struct CffTrampolineEntry {
    Rva        original_func_rva;
    uint32_t   original_func_size;
    ByteBuffer flattened_code;
    std::vector<BlockPlacement> block_placements;
    uint32_t   section_offset = 0;
};

/**
 * @brief Расплющиватель CFG одной функции.
 *
 * @details Принимает CFG, трансформирует его в расплющенную форму с dispatcher.
 *          Вся оригинальная структура переходов заменяется state-machine.
 *
 *          SOLID (SRP): отвечает за трансформацию CFG одной функции.
 */
class CfgFlattener final {
public:
    /**
     * @brief Конструктор.
     * @param arch Целевая архитектура.
     * @param config Конфигурация расплющивания.
     */
    CfgFlattener(Architecture arch, FlatteningConfig config);
    ~CfgFlattener() = default;

    CfgFlattener(const CfgFlattener&) = delete;
    CfgFlattener& operator=(const CfgFlattener&) = delete;

    /**
     * @brief Расплющивает функцию, представленную CFG.
     *
     * @param cfg Граф потока управления функции.
     * @param original_code Оригинальный машинный код функции.
     * @param base_address Виртуальный адрес начала функции.
     * @param rng Генератор случайных чисел.
     * @return Результат расплющивания или ошибка.
     */
    [[nodiscard]] MxResult<FlatteningResult> flatten(
        const analysis::ControlFlowGraph& cfg,
        ByteView original_code,
        Va base_address,
        Randomizer& rng);

    [[nodiscard]] Architecture architecture() const noexcept { return arch_; }

private:
    Architecture arch_;
    FlatteningConfig config_;

    [[nodiscard]] bool is_64bit() const noexcept { return arch_ == Architecture::x64; }

    /**
     * @brief Извлекает байты блока из оригинального кода.
     */
    [[nodiscard]] ByteBuffer extract_block_code(
        const analysis::BasicBlock& block,
        ByteView original_code,
        Va base_address) const;

    /**
     * @brief Строит state transition для блока (обновление state variable).
     */
    [[nodiscard]] ByteBuffer build_state_transition(
        uint32_t next_state_id,
        x86::Reg state_reg,
        Randomizer& rng) const;
};

/**
 * @brief Проход расплющивания CFG для пайплайна защиты.
 *
 * @details Реализует IProtectionPass. Для каждого маркированного региона
 *          (или кодовой секции) строит CFG, расплющивает его и записывает
 *          результат обратно в PE-образ.
 *
 * @note Приоритет: 400 (категория cfg_transform).
 *       Требует: config.enable_cfg_flattening == true.
 *       CFF увеличивает размер кода (dispatcher + state transitions).
 *       Для размещения используется расширение секции или code cave.
 */
class CfgFlatteningPass final : public IProtectionPass {
public:
    CfgFlatteningPass() = default;
    ~CfgFlatteningPass() override = default;

    [[nodiscard]] std::string_view name() const noexcept override {
        return "CfgFlatteningPass";
    }

    [[nodiscard]] PassCategory category() const noexcept override {
        return PassCategory::cfg_transform;
    }

    [[nodiscard]] uint32_t priority() const noexcept override {
        return 400;
    }

    [[nodiscard]] MxStatus execute(ProtectionContext& ctx) override;

    [[nodiscard]] bool is_applicable(const ProtectionContext& ctx) const noexcept override;
};

} // namespace mx
