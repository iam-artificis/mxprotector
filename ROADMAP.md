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

### Cross-platform foundation
- **`mx::target::TargetInfo`** (`include/mxprotector/target/target_info.hpp`): OS × container × arch дескриптор с factory helpers для `windows_pe_x64`, `linux_elf_x64`, `linux_elf_arm64`, `macos_macho_x64`, `macos_macho_arm64`
- **`mx::target::IBinaryImage`** (`include/mxprotector/target/binary_image.hpp`): sketch абстрактного интерфейса для будущих ELF/Mach-O бекендов. Сейчас не имплементирован — только design contract для Phase 2+
- `ProtectionContext::target()` заполняется в `main.cpp` из парсенного бинаря
- Контейнер-специфичный `PackerPass` guard'ит `is_applicable()` через `ctx.target().is_windows_pe_x64()`

---

## Критические баги

### CFG Flattening нестабилен
- **Симптом:** билды с `--cfg-flattening` падают ~30-80% в зависимости от входного бинаря
- **Статус:** pre-existing, как минимум с `b31c0b1` (verified bisect'ом)
- **Где копать:** `MbaTransitionGenerator::SimulationCorrectness` — unit-тест падает с несовпадающими значениями. Это математика MBA-цепочек в CFG transitions. Подозреваю баг в генерации inverse-функции или в state encoding
- **Временный обход:** `--no-cfg-flattening`
- **Приоритет:** высокий — следующая задача

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

### 1. Починка CFG Flattening *(высокий)*
Сначала разобраться с `MbaTransitionGenerator::SimulationCorrectness`, потом прогнать стресс на реальных бинарях.

### 2. VM-handler polymorphism *(средний)*
Сейчас handler'ы на разные опкоды имеют устойчивые эпилоги (jmp dispatcher). Нужно:
- Несколько эквивалентных эпилогов (indirect jmp через scratch, ret-to-dispatcher, push+ret)
- Per-handler junk prologue (dead MOV/XOR в scratch)
- Рандомизированные scratch-slot'ы внутри 24-байтового фрейма

### 3. Handler-table key через ImageBase *(средний)*
Вместо захардкоженного `table_xor_key` вычислять его в рантайме от `ImageBase + per-build salt`. Статически в бинарнике правильного ключа нет, ASLR делает его непредсказуемым.

### 4. Packer polymorphism *(средний)*
У packer stub сейчас фиксированная структура (push/anti-debug/key-lea/per-section-loop/IAT-wipe/pop/stolen/jmp). Добавить:
- Варианты anti-debug: PEB.BeingDebugged, PEB.NtGlobalFlag (bit 0x70), KUSER_SHARED_DATA timing
- Несколько форм decrypt loop (rep-based, SIMD, simple loop)
- Рандомизация where IAT wipe happens (до/после каждого section loop)

### 5. Анти-unicorn / анти-эмуляция *(средний)*
- Проверки на недокументированные CPU-флаги (AC, ID) в VM-контексте
- Timing checks через RDTSC внутри handler'ов (редко, не на каждом)
- CPUID-анти-VM проверки в stub

### 6. Native handler expansion *(низкий)*
Добавить покрытие generic лифтинга для:
- `shl/shr/sar` с рег-операндами
- `imul` r/m64, r64, imm
- `cmov*` семейство
- Расширенные bit-ops (`bt`, `bts`, `btr`)

### 7. Инфраструктура тестирования *(низкий)*
- Smoke-тест, проверяющий что в выходном бинаре реально присутствуют patterns: XOR handler table, XOR vflags scramble, рандомизированный reg mapping
- Diff-тест двух билдов одного input'а: должны отличаться handler permutation, vflags_key, vflags_rol, XOR keys, reg order, section names, packer key
- Full-stack стресс `--packer --cfg-flattening` после починки CFG

---

## Cross-platform plan

Целевая поддержка (в порядке приоритета):
1. **Linux ELF x86_64** — основной secondary target
2. **Linux ELF arm64** — следующий шаг
3. **macOS Mach-O x86_64 / arm64** — tertiary

Текущий статус: **Phase 1 готов** — интерфейсы объявлены, `TargetInfo` прокинут через `ProtectionContext`, контейнер-специфичные пассы guard'ят `is_applicable()`.

### Фазы миграции

**Phase 1 — Foundation (done):**
- `include/mxprotector/target/target_info.hpp` — `TargetInfo`, `Os`, `ContainerFormat`, `Arch` enums
- `include/mxprotector/target/binary_image.hpp` — `IBinaryImage`, `IBinaryImageParser`, `IBinaryImageBuilder` sketch-интерфейсы
- `ProtectionContext::target()` + guard в `PackerPass`

**Phase 2 — PE подтягивается под интерфейс:**
- `PeImage` начинает implement `IBinaryImage`
- `PeParser` становится `IBinaryImageParser`
- `PeBuilder` становится `IBinaryImageBuilder`
- `ProtectionContext::image_` ретайп на `std::unique_ptr<IBinaryImage>` (имея PE как единственную реализацию — миграция прозрачна)
- Существующие пассы компилируются без изменений

**Phase 3 — ELF parser/builder:**
- `ElfImage`, `ElfParser`, `ElfBuilder` в `src/builder/elf/`
- Детект контейнера по magic в main.cpp: `MZ` → PE, `\x7fELF` → ELF
- `TargetInfo` заполняется из ELF-бекенда
- VM-пасс работает как есть (он уже container-agnostic на уровне байткодогенерации — только x64 encoding внутри)

**Phase 4 — Target-specific пассы:**
- Linux-версия `PackerPass`: ELF-совместимый decrypt stub, Linux syscalls вместо PEB
- Linux анти-отладка: ptrace checks, `/proc/self/status:TracerPid`
- macOS аналоги: `sysctl(KERN_PROC, KERN_PROC_PID)` checks

**Phase 5 — Architecture abstraction:**
- `IArchEncoder` интерфейс (x64 encoder — текущий; arm64 encoder — новый)
- VM runtime generator параметризуется encoder'ом
- arm64 backend переиспользует lifter+mutation+obfuscation, заменяет только машкодогенерацию

### "Непортируемые" фичи

Часть защит физически привязана к конкретной платформе:
- **PE header erasure, anti-debug через PEB, IAT destruction**: Windows-only. Остаются в PE-версии `PackerPass`
- **Linux-специфика** (ptrace, `/proc` self-check): новый `LinuxPackerPass` с `is_applicable(linux_elf)`
- **x86-специфичные VM фичи** (vEFLAGS, rolling-key cipher через pushfq/popfq): остаются в `x64_vm_runtime_gen.cpp`. arm64 получит собственный `arm64_vm_runtime_gen.cpp` с NZCV-based flag handling

Каждый пасс либо **target-agnostic** (мутация байт через лифтер), либо **target-specific** с явным guard'ом. Пайплайн сам по себе платформа-нейтрален.

---

## Вне scope

- Cross-process injection stub
- .NET / managed target support
- Сетевая лицензия / DRM-хуки
- JIT-compiled stub (runtime-assembled stub code)
- Hell's Gate / direct syscalls (эксперимент с custom loader'ом откатан — может вернуться как опциональная фича)
