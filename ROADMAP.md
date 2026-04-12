# MxProtector Roadmap

Статус на 2026-04-13. Фичи перечислены в порядке убывания приоритета.

---

## Готово

### VM движок
- Threaded-code VM dispatch без центрального dispatcher
- Зашифрованная handler table (per-build XOR key)
- Rolling-key stream cipher для bytecode
- MBA-варианты handlers, junk polymorphism в bytecode
- VJMP / VJCC (виртуальные ветки внутри VM)
- Cross-VM jumps: крупные регионы (≥8 insns) делятся на независимые sub-VMs
- **Dynamic register ordering**: per-build Fisher–Yates перестановка 16 слотов VM-контекста, random junk-slot, remap на этапе эмиссии байткода — хендлеры по-прежнему используют uniform `slot*8` адресацию, но что в каком слоте лежит — per-build random
- **vEFLAGS с rol/ror + full 32-bit key**: `rol(rflags, n) ^ key`, `n ∈ [1, 31]`, ключ полностью случайный u32. Exit явно descramble перед popfq → cross-VM sub-VMs полностью независимы по (key, rol)
- **vEFLAGS polymorphism**: 3 варианта для store path (`rax rol-first`, `rax xor-first`, in-place memory), 3 для popfq path, 4 для in-slot transforms, 2 для VJCC-to-ecx. Per-site random выбор

### PE pipeline
- **Self-unpacking packer (multi-section)**: `.text`, VM blob, CFF трамплины шифруются одним 256-байтным ключом, stub расшифровывает по per-section циклу. Ключевой индекс `dl` переносится между секциями — разные секции используют непересекающиеся срезы ключа
- **Anti-debug в stub**: PEB.BeingDebugged сдвигает стартовое значение `dl` на 1 → все расшифрованные байты сдвинуты на 1 → программа молча портится. Невозможно просто zeros'ом отменить проверку
- **IAT destruction**: stub зануляет Import Directory после того как Windows loader резолвнул импорты → дампер не восстановит таблицу импортов
- **Stolen bytes**: первые инструкции OEP (~13 байт) переезжают в stub; `.text` имеет дыру на своём OEP'е, но выполнение идёт через stub
- CFF трамплины, mutation engine, opaque predicates
- **Random section names**: 3 секции (vm / cff / packer) берутся из пула plausible MSVC/clang имён (`.rdata2`, `.xtors`, `.xdata2`, `.tls1`, `.CRT$XC`, `.00cfg` ...). `--debug-sections` возвращает `.mxvm/.mxprot1/.mxpack`

### Cross-platform foundation (container axis)
- **`mx::target::TargetInfo`** (`include/mxprotector/target/target_info.hpp`): OS × container × arch дескриптор с factory helpers для `windows_pe_x64`, `linux_elf_x64`, `linux_elf_arm64`, `macos_macho_x64`, `macos_macho_arm64`
- **`mx::target::IBinaryImage`** (`include/mxprotector/target/binary_image.hpp`): sketch абстрактного интерфейса для будущих ELF/Mach-O бекендов. Сейчас не имплементирован — только design contract для Phase 2+
- `ProtectionContext::target()` заполняется в `main.cpp` из парсенного бинаря
- Контейнер-специфичный `PackerPass` guard'ит `is_applicable()` через `ctx.target().is_windows_pe_x64()`

### Cross-platform foundation (architecture axis)
- **`mx::arch::ArchInfo`** (`include/mxprotector/arch/arch_info.hpp`): fine-grained дескриптор — `ArchVariant` (armv8-a, armv8.2-a, cortex-m4, ...), `ArchProfile` (A/R/M), `ArchFeatures` (NEON, crypto, LSE, MTE, PAC). Factory helpers для common конфигураций: `x64_baseline()`, `x64_modern()`, `arm64_v8a_application()`, `arm64_v82a_crypto()`, `cortex_m4()`
- **`mx::arch::ICodeEmitter`** (`include/mxprotector/arch/code_emitter.hpp`): абстрактный emitter с операциями mov/load/store/arith/jmp/jcc/call/ret + labels. Ровно то что passes реально используют — без попытки покрыть весь ISA
- **`mx::arch::IVmBackend`** (`include/mxprotector/arch/vm_backend.hpp`): VM runtime generator как target-agnostic engine + per-arch backend. x64 backend = текущий `vm_runtime_gen.cpp` после будущего рефакторинга; arm64 backend — новая реализация с 31 GPR контекстом, NZCV flag handling, LDR/EOR/STR stream cipher

---

## Критические баги (закрыты)

### Bug B: CFG Flattening нестабилен — FIXED
- **Симптом (был):** билды с `--cfg-flattening` падали ~30-80%
- **Корневая причина:** два бага в `OpaquePredicateGenerator::gen_quadratic_parity`:
  1. **Hardcoded register**: использовался `test al, 1` (опкод `A8 01`), который всегда
     тестирует AL, независимо от того какой регистр выбрал `pick_safe_register`. Для
     5 из 6 safe-регистров тест проверял случайный байт AL, не результат вычисления.
  2. **Математика была неверна с самого начала**: последовательность
     `mov reg, reg; add reg, 1; imul reg, reg` вычисляет `(x+1)^2`, не `x * (x+1)`.
     `(x+1)^2` имеет 50% шанс быть нечётным, поэтому "always-true" предикат был
     таким на 50%. Баг #1 маскировал баг #2 за счёт случайности содержимого AL.
- **Фикс:**
  - `test reg, 1` через 32-bit форму `F7 /0 imm32` — работает для любого safe-регистра
  - Использовать два разных регистра: скопировать `x` в `scratch`, `inc scratch`,
    `imul reg, scratch` → настоящее `x * (x+1)`, всегда чётное
  - Исправлен ложно-положительный тест `SimulationCorrectness`, который ожидал
    ведущий `MOV` когда генератор его не эмитит (при `state_preserved=true`).
    Разделил на два теста: `_StatePreserved` и `_StateNotPreserved`
- **Результат:** 140/140 тестов проходят при `level=standard --no-packer` и
  140/140 при `level=maximum` (полный пайплайн — Mutation + Obfuscation + VM +
  CFF + Packer)

---

## Архитектурные решения

### Отказ от отдельного EncryptionPass
Ранее существовал `EncryptionPass`, который писал конфиг `.mxrt` для сильного custom loader'а (ChaCha20/AES, Hell's Gate syscalls, manual import resolver). Этот loader никогда не был встроен в выходной PE — это была оставшаяся Phase 8+ задача. В итоге `EncryptionPass` шифровал секции, но в бинаре не было кода, который умел их расшифровать → любой билд с encryption ломался.

**Решение:** полный отказ от `EncryptionPass` и всей stub_main инфраструктуры. Все шифрование теперь делает `PackerPass` с расширенным multi-section stub:
- Защита всех важных секций (`.text`, VM blob, CFF трамплины) одним механизмом
- Встроенный stub сам по себе — не зависит от внешнего loader'а
- 256-байтный XOR с per-section смещением ключа — достаточно для on-disk защиты
- Anti-debug + IAT destruction + stolen bytes встроены в тот же stub

Удалены:
- `src/builder/protection/encryption/` (ChaCha20Encryptor, AesEncryptor, EncryptionPass)
- `src/stub/` (весь PIC loader: stub_main, section_decryptor, import_resolver, relocation_fixer, Hell's Gate resolver, gate.asm, entry.asm, chacha20_pic, aes_pic, header_eraser)
- `include/mxprotector/stub/stub_config.hpp`
- `include/mxprotector/protection/encryption/`
- `tests/unit/encryption_test.cpp`, `tests/unit/syscall_engine_test.cpp`
- `tests/integration/` (syscall live test для удалённого gate.asm)
- CLI флаги `--no-encryption`, `--prefer-aes`
- `ProtectionConfig::enable_encryption`, `ProtectionConfig::prefer_aes`
- `SectionNameMap::mxrt`
- `option(MXPROTECTOR_BUILD_STUB ...)` в top-level CMakeLists

Если в будущем захочется анти-EDR режима (bypass NTDLL hooks через direct syscalls), можно добавить новый опциональный `HellGatePackerPass` — но как **опция поверх** текущего packer'а, а не как альтернативная вселенная. И уже с законченной имплементацией, не как dangling fragment.

---

## Следующие шаги (по приоритету)

### 1. VM-handler polymorphism *(средний)*
Сейчас handler'ы на разные опкоды имеют устойчивые эпилоги (jmp dispatcher). Нужно:
- Несколько эквивалентных эпилогов (indirect jmp через scratch, ret-to-dispatcher, push+ret)
- Per-handler junk prologue (dead MOV/XOR в scratch)
- Рандомизированные scratch-slot'ы внутри 24-байтового фрейма

### 2. Handler-table key через ImageBase *(средний)*
Вместо захардкоженного `table_xor_key` вычислять его в рантайме от `ImageBase + per-build salt`. Статически в бинарнике правильного ключа нет, ASLR делает его непредсказуемым.

### 3. Packer polymorphism *(средний)*
У packer stub сейчас фиксированная структура (push/anti-debug/key-lea/per-section-loop/IAT-wipe/pop/stolen/jmp). Добавить:
- Варианты anti-debug: PEB.BeingDebugged, PEB.NtGlobalFlag (bit 0x70), KUSER_SHARED_DATA timing
- Несколько форм decrypt loop (rep-based, SIMD, simple loop)
- Рандомизация где происходит IAT wipe (до/после каждого section loop)

### 4. Анти-unicorn / анти-эмуляция *(средний)*
- Проверки на недокументированные CPU-флаги (AC, ID) в VM-контексте
- Timing checks через RDTSC внутри handler'ов (редко, не на каждом)
- CPUID-анти-VM проверки в stub

### 5. Native handler expansion *(низкий)*
Добавить покрытие generic лифтинга для:
- `shl/shr/sar` с рег-операндами
- `imul` r/m64, r64, imm
- `cmov*` семейство
- Расширенные bit-ops (`bt`, `bts`, `btr`)

### 6. Инфраструктура тестирования *(низкий)*
- Smoke-тест, проверяющий что в выходном бинаре реально присутствуют patterns: XOR handler table, XOR vflags scramble, рандомизированный reg mapping
- Diff-тест двух билдов одного input'а: должны отличаться handler permutation, vflags_key, vflags_rol, XOR keys, reg order, section names, packer key
- Fuzz-style стресс сотни input'ов × full pipeline

---

## Cross-platform plan

Эта и следующая секция расписывают миграцию по ДВУМ независимым осям:

- **Container** (PE / ELF / Mach-O) — "какой парсер и builder работает с файлом"
- **Architecture** (x64 / arm64 / cortex-m) — "как выглядит машинный код внутри"

Эти оси ортогональны. Windows PE x64 и Linux ELF x64 делят одну arch-backend,
но разные container-backend. Linux ELF arm64 и Android ELF arm64 делят один
arch-backend, но отличаются target-specific passes. Пайплайн должен уметь
любую комбинацию: для каждого target выбирается `(container backend, arch backend)`.

### Container axis (PE/ELF/Mach-O)

Целевая поддержка по контейнеру:
1. **Windows PE** — единственный сейчас, полный pipeline
2. **Linux ELF** — primary secondary target (embedded Linux, Android, desktop)
3. **macOS Mach-O** — tertiary (Apple Silicon десктоп/ноутбук)

Статус: **Phase 1 container foundation готов** — `target::TargetInfo`,
`target::IBinaryImage` sketch, `ProtectionContext::target()`,
container-specific guard в `PackerPass`.

**Phase 1 (done):**
- `include/mxprotector/target/target_info.hpp` — `TargetInfo`, `Os`, `ContainerFormat`, `Arch` enums
- `include/mxprotector/target/binary_image.hpp` — `IBinaryImage`, `IBinaryImageParser`, `IBinaryImageBuilder`
- `ProtectionContext::target()` + guard в `PackerPass`

**Phase 2 — PE tucks under the interface:**
- `PeImage` начинает `implement IBinaryImage`
- `PeParser` становится `IBinaryImageParser`, `PeBuilder` — `IBinaryImageBuilder`
- `ProtectionContext::image_` перетипизируется в `std::unique_ptr<IBinaryImage>`
- Существующие passes компилируются без изменений

**Phase 3 — ELF parser/builder:**
- `ElfImage`, `ElfParser`, `ElfBuilder` в `src/builder/elf/`
- Детект контейнера по magic в `main.cpp`: `MZ` → PE, `\x7fELF` → ELF
- `TargetInfo` заполняется из выбранного парсера

**Phase 4 — Target-specific passes:**
- Linux-версия packer: ELF-совместимый decrypt stub, `syscall`-based init
- Linux анти-отладка: ptrace checks, `/proc/self/status:TracerPid`
- macOS Mach-O parser + ptrace/sysctl анти-debug

### Architecture axis (x64 / arm64 / cortex-m)

Целевая поддержка по архитектуре (в порядке приоритета):
1. **x86-64** — текущая, полный pipeline
2. **ARMv8-A (arm64)** — следующий шаг после ELF container backend
   - **Embedded Linux arm64** (Raspberry Pi, роутеры, IP камеры, IoT шлюзы) — ~80% IoT
   - **Android arm64** — поверх embedded Linux backend, + SELinux-aware
   - **macOS arm64** (Apple Silicon) — поверх Mach-O backend
3. **Cortex-M** (ARMv6-M / v7-M / v7E-M) — experimental, bare-metal и RTOS
   firmware. Только после того как v8-A работает, и только если есть
   реальный пользовательский спрос (firmware protection для IoT-девайсов).
4. **Cortex-R** — не в scope. Специализированный real-time target, рынок
   узкий. Если понадобится — переиспользует бОльшую часть Cortex-A backend'а.

Статус: **Phase 1 arch foundation готов** — `arch::ArchInfo`, `arch::ICodeEmitter`,
`arch::IVmBackend` sketch-интерфейсы объявлены, реализации нет.

**Phase 1 arch (done):**
- `include/mxprotector/arch/arch_info.hpp` — `ArchInfo`, `ArchVariant`, `ArchProfile`, `ArchFeatures` + factory helpers (`x64_baseline`, `arm64_v8a_application`, ...)
- `include/mxprotector/arch/code_emitter.hpp` — `ICodeEmitter` sketch: mov/load/store/arith/jmp/jcc/call/ret + labels
- `include/mxprotector/arch/vm_backend.hpp` — `IVmBackend` sketch: VM runtime generation абстрагирована от x64 bytes

**Phase 2 arch — x64 tucks under the interface:**
- Существующий `vm_runtime_gen.cpp` раскладывается на:
  - `VmRuntimeEngine` (target-agnostic policy: permutation, key generation, variant selection, cross-VM split, bytecode assembly)
  - `X64VmBackend : IVmBackend` (x64-specific mechanics: push/pop, pushfq, rflags scramble, handler dispatch via lea+jmp, stream cipher)
- `X86CodeEmitter : ICodeEmitter` — обёртка над существующим `x86_code_emitter.cpp`
- Ничего в build output не меняется — та же x64 сборка, тот же байт-паттерн

**Phase 3 arch — arm64 VM backend:**
- `Arm64CodeEmitter : ICodeEmitter` — A64 instruction encoding, 31 GPRs
- `Arm64VmBackend : IVmBackend`:
  - 31-slot VM context вместо 16 (vm_bytecode operand size поднимается до 5 бит)
  - Flag handling через MRS/MSR NZCV, либо computed-predicate в GPRs
  - Handler dispatch через ADR + LDR + BR table
  - Stream cipher через LDR/LDR/EOR/STR (4-byte unit)
  - Native escape: arm64 инструкции выполняются в своём frame
- Arm64-specific mutation rules (`mov x0, #0` → `eor x0, x0, x0` и т.д.)

**Phase 4 arch — Linux/Android arm64 target passes:**
- `LinuxArm64PackerPass`: ELF stub на arm64, ptrace-based anti-debug, Android-совместимость
- Проверки на Android Runtime hooks (Frida, Xposed)

**Phase 5 arch — experimental Cortex-M (optional):**
- Thumb-2 only encoding, ограниченный набор инструкций
- Нет MMU → нет ASLR → handler-table key через ImageBase бесполезен
- Stub loader с учётом Flash/RAM layout
- Нет dynamic linker → imports резолвятся статически на этапе сборки firmware
- Вероятно понадобится custom container format (raw binary + manifest)

### "Непортируемые" фичи

Часть защит физически привязана к конкретной платформе/архитектуре:

| Фича | Где ограничена | Примечание |
|---|---|---|
| PE header erasure, PEB anti-debug, IAT destruction | Windows PE | Остаются в PE-версии `PackerPass` |
| vEFLAGS через RFLAGS scramble | x86-64 | Arm64 backend использует NZCV-based или computed-predicate подход |
| Rolling-key stream cipher через pushfq/popfq | x86-64 | Arm64 использует LDP/STP + EOR |
| ptrace-based anti-debug | Linux/Android | Отдельный `LinuxPackerPass` |
| `sysctl` KERN_PROC anti-debug | macOS | Отдельный `MacOSPackerPass` |
| TrustZone-M anti-tamper | Cortex-M33 | Experimental, требует hardware support |

Каждый pass либо **target-agnostic** (напр. мутация байт через лифтер),
либо **target-specific** с явным `is_applicable()` guard'ом. Pipeline сам
по себе container- и arch-нейтрален.

---

## Вне scope

- Cross-process injection stub
- .NET / managed target support
- Сетевая лицензия / DRM-хуки
- JIT-compiled stub (runtime-assembled stub code)
- Hell's Gate / direct syscalls (эксперимент с custom loader'ом откатан — может вернуться как опциональная фича)
