# MxProtector — Claude Agent Working Notes

Короткий living-документ для агентов (Claude Code / любой LLM-агент), работающих с
кодовой базой MxProtector. Подробный план — в `ROADMAP.md`; здесь только то, что
помогает агенту ориентироваться быстро.

## Что это

C++23 protector для бинарников. Сегодня поддерживается **Windows PE x64**. Pipeline
защиты собран из независимых passes (SOLID, `IProtectionPass` interface). Cross-platform
(Linux ELF, arm64, Mach-O) — фундамент заложен (см. `include/mxprotector/target/`),
реализация по фазам в ROADMAP.

## Текущий pipeline (в порядке исполнения)

| Приоритет | Pass                   | Что делает                                              |
|-----------|------------------------|---------------------------------------------------------|
| 100       | `MutationPass`         | Substitution, junk, splitting, register reassignment    |
| 200       | `ObfuscationPass`      | Opaque predicates, MBA, constant unfolding              |
| 300       | `VirtualizationPass`   | Лифтинг MX_VM_BEGIN/END регионов в VM bytecode          |
| 400       | `CfgFlatteningPass`    | Trampoline в `.mxprot1`, dispatcher, MBA transitions    |
| 800       | `PackerPass`           | Multi-section XOR + anti-debug + stolen bytes + IAT wipe|

Нет больше `EncryptionPass` / stub_main loader'а — см. "Архитектурные решения" ниже.

## Как запустить и протестить

Сборка builder'а через bundled VS CMake (важно — новейший CMake из PATH может сломаться
на compiler detection):

```bash
"C:/Program Files/Microsoft Visual Studio/2022/Community/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe" \
  --build build --config Release --target mxprotector_builder
```

Protect тестовую программу:

```bash
cd build_testapp
../build/src/builder/Release/mxprotector_builder.exe \
  -i test_vm_showcase.exe -o t.exe -l strong --no-cfg-flattening
./t.exe   # должно вывести "ALL 22 CHECKS PASSED"
```

Стресс-тест (15 рандомных билдов):

```bash
for i in $(seq 1 15); do
  ../build/src/builder/Release/mxprotector_builder.exe \
    -i test_vm_showcase.exe -o t.exe -l strong --no-cfg-flattening >/dev/null 2>&1
  ./t.exe >/dev/null 2>&1 || echo "FAIL"
done
```

## Важные архитектурные решения

### Отказ от EncryptionPass / stub_main loader'а
Исторически был отдельный `EncryptionPass` (ChaCha20/AES per-section), который ожидал
полноценный PIC stub_main с Hell's Gate syscall'ами, import resolver'ом и т.д. Этот
stub loader никогда не дописали до интеграции в выходной PE — любой билд с encryption
ломался, потому что секции зашифрованы, а в бинаре нет кода чтобы их расшифровать.

**Решение**: `EncryptionPass` + `src/stub/` полностью удалены. Всю работу по шифрованию
делает `PackerPass`: multi-section XOR с единым 256-байтным ключом (индекс `dl` переносится
между секциями), inline stub, anti-debug через PEB, IAT wipe, stolen bytes.

Если в будущем понадобится anti-EDR режим с прямыми syscall'ами — добавляется как
**опциональная** фича поверх packer'а, не как параллельная вселенная.

### Cross-platform foundation (Phase 1 ready)
`include/mxprotector/target/target_info.hpp` определяет `TargetInfo{os, container, arch}`
с factory helpers. `include/mxprotector/target/binary_image.hpp` — sketch абстрактного
`IBinaryImage` интерфейса (пока без реализации — PE код ещё не мигрирован).

Container-specific passes (`PackerPass`) guard'ят `is_applicable()` через
`ctx.target().is_windows_pe_x64()`, чтобы при добавлении ELF бекенда они корректно
пропускались.

### Рандомизация имён секций
MxProtector добавляет 3 секции (vm / cff / packer). Имена per-build рандомизируются
из пула plausible MSVC/clang имён (`.rdata2`, `.xtors`, `.xdata2`, `.tls1`, `.CRT$XC`,
`.00cfg` ...). `--debug-sections` возвращает фиксированные `.mxvm/.mxprot1/.mxpack`
для удобства отладки.

## Слои с известными багами

### CFG Flattening нестабилен
`--cfg-flattening` ломает 30-80% билдов. Pre-existing. Первый подозреваемый —
`MbaTransitionGenerator::SimulationCorrectness` (падает в unit-тестах). См. ROADMAP.

**Обход**: `--no-cfg-flattening`.

## Как правильно расширять

### Добавить новый protection pass
1. Создать `include/mxprotector/protection/<name>/...hpp` с классом `XxxPass : IProtectionPass`
2. `is_applicable()` должен guard'ить target через `ctx.target()` если pass container/arch-specific
3. Реализовать `execute(ProtectionContext&)` — без side effects в глобальном стейте
4. Зарегистрировать в `src/builder/main.cpp`
5. Добавить в `src/builder/CMakeLists.txt`
6. Написать unit test в `tests/unit/...`

### Добавить новый target (Linux ELF и т.д.)
См. ROADMAP.md → Cross-platform plan → Phase 2/3.

### Расширить VM
`src/builder/protection/vm/vm_runtime_gen.cpp` — генератор VM stub'а. Основные точки
polymorphism: store variant, popfq variant, in-slot transform, VJCC variant. Каждый
call site через `pick_xxx_variant(rng)`. Добавляя новый variant — расширить enum,
добавить case в emit функцию, инкрементировать `kCount`.

## Что НЕ делать

- **Не возвращать EncryptionPass / stub_main loader как "альтернативный" путь**.
  Если нужна сильная криптография — добавить в packer как ChaCha20 inline вариант,
  не как параллельную вселенную.
- **Не хардкодить имена секций** — всегда через `ctx.section_names().vm` / `.cff` / `.packer`.
- **Не хардкодить `is_applicable()` без target guard** для container/arch-specific passes.
- **Не коммитить** unused фрагменты "на будущее". Если код не интегрирован в pipeline —
  удалить; git history сохранит.

## Справочник файлов

- `ROADMAP.md` — приоритизированный roadmap (авторитетный документ)
- `include/mxprotector/core/context.hpp` — ProtectionContext, SectionNameMap
- `include/mxprotector/target/target_info.hpp` — TargetInfo, Os/Container/Arch enums
- `include/mxprotector/target/binary_image.hpp` — future cross-platform interface (sketch)
- `include/mxprotector/config/protection_config.hpp` — config + level presets
- `src/builder/main.cpp` — pipeline assembly, section name generation
- `src/builder/protection/vm/vm_runtime_gen.cpp` — VM runtime codegen (x64, ~2K lines)
- `src/builder/protection/packer/packer_pass.cpp` — multi-section packer + stub emit
