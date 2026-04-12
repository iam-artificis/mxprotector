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
- **Dynamic register ordering** (`21a2ea2`): per-build Fisher–Yates перестановка 16 слотов VM-контекста, random junk-slot, remap на этапе эмиссии байткода — хендлеры по-прежнему используют uniform `slot*8` адресацию, но что в каком слоте лежит — per-build random
- **vEFLAGS с rol/ror + full 32-bit key** (`efe3b28`): `rol(rflags, n) ^ key`, `n ∈ [1, 31]`, ключ полностью случайный u32 (без маски). Exit явно descramble перед popfq → cross-VM sub-VMs полностью независимы по (key, rol)
- **vEFLAGS polymorphism** (`1874450`): 3 варианта для store path (`rax rol-first`, `rax xor-first`, in-place memory), 3 для popfq path, 4 для in-slot transforms, 2 для VJCC-to-ecx. Per-site random выбор через rng

### PE pipeline
- Self-unpacking packer: anti-debug (PEB.BeingDebugged), stolen bytes на OEP, полиморфный stub
- IAT destruction (Import Directory wipe на runtime после расшифровки)
- CFF трамплины, mutation engine, opaque predicates
- **Random section names** (`0ce99da`): 4 секции (vm/cff/mxrt/packer) берутся из пула из 20 plausible MSVC/clang имён (`.rdata2`, `.xtors`, `.xdata2`, `.tls1`, `.CRT$XC`, `.00cfg` ...). `--debug-sections` возвращает старые `.mxvm/.mxprot1/.mxrt/.mxpack`
- **Stub loader лечит runtime-config по магическому числу** (`73b9316`): раньше стаб искал `.mxrt` по имени — теперь сканирует все секции и сверяет первые 8 байт с `{MXRT_MAGIC, MXRT_VERSION}`

### Cross-platform foundation
- **`mx::target::TargetInfo`** (`include/mxprotector/target/target_info.hpp`): OS × container × arch дескриптор с factory helpers для `windows_pe_x64`, `linux_elf_x64`, `linux_elf_arm64`, `macos_macho_x64`, `macos_macho_arm64`
- **`mx::target::IBinaryImage`** (`include/mxprotector/target/binary_image.hpp`): sketch абстрактного интерфейса для будущих ELF/Mach-O бекендов. Сейчас не имплементирован — только design contract для Phase 2+
- `ProtectionContext::target()` заполняется в `main.cpp` из парсенного бинаря
- Контейнер-специфичные пассы (`PackerPass`, `EncryptionPass`) guard'ят `is_applicable()` через `ctx.target().is_windows_pe_x64()`

---

## Критические баги (должны быть починены до следующих фич)

### A. Encryption / Packer pipeline сломан
- **Симптом:** любой билд с `--encryption` или `--packer` (даже `-l minimal --packer`) производит бинарь, который не запускается
- **Статус:** pre-existing, подтверждено bisect'ом через все 5 видимых коммитов вплоть до initial `6e6d98e`
- **Где копать:** `src/stub/loader/` (entry.asm, stub_main, section_decryptor), `src/builder/protection/packer/packer_pass.cpp` (rel32 патчинг и stolen-bytes логика), проверка соответствия `mxrt` конфигурации тому, что ожидает stub
- **Временный обход:** использовать `--no-packer --no-encryption`. VM + Mutation + Obfuscation работают стабильно
- **Приоритет:** высокий — без этого пакер и шифрование бесполезны

### B. CFG Flattening нестабилен
- **Симптом:** билды с `--cfg-flattening` падают ~30-80% в зависимости от входного бинаря
- **Статус:** pre-existing, как минимум с `b31c0b1` (verified в предыдущей сессии)
- **Где копать:** `MbaTransitionGenerator::SimulationCorrectness` — unit-тест падает с несовпадающими значениями. Это математика MBA-цепочек в CFG transitions. Подозреваю бага в генерации inverse-функции или в state encoding
- **Временный обход:** `--no-cfg-flattening`
- **Приоритет:** высокий

---

## Следующие шаги (по приоритету)

### 1. Починка encryption/packer (критичный баг A)
Без рабочего encryption/packer мы защищаем только VM-регионы — а большая часть кода остаётся в открытом виде. Это главный блокер практической применимости MxProtector.

### 2. Починка CFG Flattening (критичный баг B)
Сначала разобраться с `MbaTransitionGenerator::SimulationCorrectness`, потом прогнать стресс на реальных бинарях.

### 3. VM-handler polymorphism *(средний приоритет)*
Сейчас handler'ы на разные опкоды имеют устойчивые эпилоги (jmp dispatcher). Нужно:
- Несколько эквивалентных эпилогов (indirect jmp через scratch, ret-to-dispatcher, push+ret)
- Per-handler junk prologue (dead MOV/XOR в scratch)
- Рандомизированные scratch-slot'ы внутри 24-байтового фрейма

### 4. Handler-table key через ImageBase *(средний)*
Идея со звёздочкой из ранней планировки. Вместо захардкоженного `table_xor_key` вычислять его в рантайме от `ImageBase + per-build salt`. Статически в бинарнике правильного ключа нет, ASLR делает его непредсказуемым.

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
- Отдельный smoke-тест, проверяющий что в выходном бинаре реально присутствуют patterns: XOR handler table, XOR vflags scramble, рандомизированный reg mapping
- Diff-тест двух билдов одного input'а: должны отличаться handler permutation, vflags_key, vflags_rol, XOR keys, reg order, section names
- Restart-reuse стресс (полный `--packer --cfg-flattening --encryption` когда они заработают)

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
- `ProtectionContext::target()` + guards в encryption/packer passes

**Phase 2 — PE подтягивается под интерфейс:**
- `PeImage` начинает implement `IBinaryImage`
- `PeParser` становится `IBinaryImageParser`
- `PeBuilder` становится `IBinaryImageBuilder`
- `ProtectionContext::image_` ретайп на `std::unique_ptr<IBinaryImage>` (имея PE как единственную реализацию — миграция прозрачна)
- Существующие пассы компилируются без изменений (интерфейс покрывает всё, что они используют сегодня)

**Phase 3 — ELF parser/builder:**
- `ElfImage`, `ElfParser`, `ElfBuilder` в `src/builder/elf/`
- Детект контейнера по magic в main.cpp: `MZ` → PE, `\x7fELF` → ELF
- `TargetInfo` заполняется из ELF-бекенда
- VM-пасс работает как есть (он уже архитектура-нейтральный на уровне контейнера — только x64 encoding внутри)

**Phase 4 — Target-specific пассы:**
- Linux-версия `PackerPass`: вместо PE stub — ELF-совместимый decrypt stub, Linux syscalls вместо Nt*
- Linux-версия анти-отладки: ptrace checks, `/proc/self/status:TracerPid`
- macOS аналоги: `sysctl(KERN_PROC, KERN_PROC_PID)` checks

**Phase 5 — Архитектура-абстракция:**
- `IArchEncoder` интерфейс (x64 encoder — текущий; arm64 encoder — новый)
- VM runtime generator параметризуется encoder'ом
- arm64 backend переиспользует lifter+mutation+obfuscation, заменяет только машкодогенерацию

### Что делать с "неносимыми" фичами

Часть защит физически привязана к конкретным ОС/архитектурам:
- **PE header erasure, anti-debug через PEB, IAT destruction**: Windows-only. Остаются в `PackerPass::is_applicable(windows_pe)`
- **Linux-специфика** (ptrace детект, `/proc` self-check): новый `LinuxAntiDebugPass` с `is_applicable(linux)`
- **x86-специфичные VM фичи** (vEFLAGS, rolling-key cipher через pushfq/popfq): остаются в `x64_vm_runtime_gen.cpp`. arm64 получит собственный `arm64_vm_runtime_gen.cpp` с NZCV-based flag handling

Каждый пасс либо **target-agnostic** (мутация байт через лифтер), либо **target-specific** с явным guard'ом. Пайплайн сам по себе платформа-нейтрален.

---

## Вне scope

- Cross-process injection stub
- .NET / managed target support
- Сетевая лицензия / DRM-хуки
- JIT-compiled stub (runtime-assembled stub code)
