# MxProtector Roadmap

Статус на 2026-04-13. Легенда маркеров:

| Маркер | Значение |
|---|---|
| ✅ | Реализовано, стабильно работает в пайплайне |
| ⏳ | В процессе / текущий шаг |
| 📋 | Запланировано, ещё не начато |
| ❌ | Отклонено (см. секцию "Отклонённые идеи") |

---

## Готово

### VM движок
- ✅ Threaded-code VM dispatch без центрального dispatcher
- ✅ Зашифрованная handler table (per-build XOR key)
- ✅ Rolling-key stream cipher для bytecode
- ✅ MBA-варианты handlers, junk polymorphism в bytecode
- ✅ VJMP / VJCC (виртуальные ветки внутри VM)
- ✅ Cross-VM jumps: крупные регионы (≥8 insns) делятся на независимые sub-VMs
- ✅ **Dynamic register ordering**: per-build Fisher–Yates перестановка 16 слотов VM-контекста, random junk-slot, remap на этапе эмиссии байткода
- ✅ **vEFLAGS с rol/ror + full 32-bit key**: `rol(rflags, n) ^ key`, `n ∈ [1, 31]`, ключ полностью случайный u32. Exit явно descramble перед popfq → cross-VM sub-VMs полностью независимы по (key, rol)
- ✅ **vEFLAGS polymorphism**: 3 варианта store, 3 popfq, 4 in-slot, 2 VJCC-to-ecx. Per-site random
- ✅ **VM-handler polymorphism**: per-handler junk prologue (0–8 NOP bytes), tail dispatch через 13 random base regs × 2 dispatch shapes (`jmp reg` vs `push reg; ret`)
- ✅ **Handler-table key через PEB.ImageBase**: ключ вычисляется в рантайме из `PEB.ImageBaseAddress`, dispatches используют `xor eax, [rsp+disp8]` вместо `xor eax, imm32`. Работает только когда packer страйпит ASLR
- ✅ **Entry-stub MBA**: вычисление `ImageBase_low32 → table_xor_key` через случайную цепочку 6–12 arithmetic ops (переиспользует `MbaTransitionGenerator`), вместо одиночного `xor eax, salt`
- ✅ **Handler-table integrity check**: entry stub XOR-суммирует все encrypted table entries и сравнивает с build-time expected value. При tampering (debugger memory patch) XOR-сумма отличается → silently corrupts key → все dispatches ломаются. Без branch'а — не NOP-нуть
- ✅ **Anti-emulation checks** (`include/mxprotector/protection/anti_emulation/`, отдельный файл per-техника): 2 RDTSC-based probe (zero-delta для Unicorn/DBI, huge-delta для QEMU/Triton). Registry архитектура — per-build random 1..2 checks. Каждый XOR'ит 0 (real HW) или random non-zero mask (emulated) в key slot. CPUID hypervisor check реализован но не в default registry из-за false-positives на Windows 11 + VBS/Hyper-V/WSL2

### PE pipeline
- ✅ **Self-unpacking packer (multi-section)**: `.text`, VM blob, CFF трамплины шифруются одним 256-байтным ключом, stub расшифровывает по per-section циклу. Ключевой индекс `dl` переносится между секциями
- ✅ **Anti-debug variant pool в packer stub**: 3 варианта (`PEB.BeingDebugged`, `PEB.NtGlobalFlag & 0x70`, `KUSER_SHARED_DATA.KdDebuggerEnabled`). Per-build random, result сдвигает start index decrypt loop'а
- ✅ **Decrypt loop variant**: 2 формы (`load-xor-store` и `memory-xor`). Per-build random
- ✅ **Randomized push/pop order** в packer stub
- ✅ **IAT destruction**: stub зануляет Import Directory после того как Windows loader резолвнул импорты
- ✅ **Stolen bytes**: первые инструкции OEP (~13 байт) переезжают в stub
- ✅ **CFG Flattening** с мутацией, opaque predicates, MBA state transitions, junk blocks
- ✅ **Random section names**: 3 секции (vm / cff / packer) берутся из пула plausible MSVC/clang имён (`.rdata2`, `.xtors`, `.xdata2`, `.tls1`, `.CRT$XC`, `.00cfg` ...). `--debug-sections` возвращает `.mxvm/.mxprot1/.mxpack`

### Cross-platform foundation (container axis)
- ✅ **`mx::target::TargetInfo`** (`include/mxprotector/target/target_info.hpp`): OS × container × arch дескриптор с factory helpers для `windows_pe_x64`, `linux_elf_x64`, `linux_elf_arm64`, `macos_macho_x64`, `macos_macho_arm64`
- ✅ **`mx::target::IBinaryImage`** (`include/mxprotector/target/binary_image.hpp`): sketch абстрактного интерфейса для будущих ELF/Mach-O бекендов. Сейчас не имплементирован — только design contract для Phase 2+
- ✅ `ProtectionContext::target()` заполняется в `main.cpp` из парсенного бинаря
- ✅ Контейнер-специфичный `PackerPass` guard'ит `is_applicable()` через `ctx.target().is_windows_pe_x64()`

### Cross-platform foundation (architecture axis)
- ✅ **`mx::arch::ArchInfo`** (`include/mxprotector/arch/arch_info.hpp`): fine-grained дескриптор — `ArchVariant` (armv8-a, armv8.2-a, cortex-m4, ...), `ArchProfile` (A/R/M), `ArchFeatures` (NEON, crypto, LSE, MTE, PAC)
- ✅ **`mx::arch::ICodeEmitter`** (`include/mxprotector/arch/code_emitter.hpp`): абстрактный emitter — sketch
- ✅ **`mx::arch::IVmBackend`** (`include/mxprotector/arch/vm_backend.hpp`): VM runtime generator абстрагирован — sketch

---

## Критические баги (закрыты)

### ✅ Bug B: CFG Flattening нестабилен — FIXED
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

### 📋 1. Расширение anti-emulation check pool *(низкий-средний)*
Дополнительные probe'ы в `protection/anti_emulation/`:
- **AC flag fidelity**: set/clear bit 18 через pushfq/popfq в user mode — некоторые эмуляторы неправильно обрабатывают reserved flags
- **FPU quirks**: x87 precision-control behaviors (rounding edge cases) редко идентичны между реальным CPU и эмулятором
- **Undocumented opcodes**: emit `D6` (SALC) или `F1` (ICEBP) — legitimate but obscure, некоторые emulators crash'атся или ловят exception
- **Scheduler timing**: timing delta across `pause` instruction (hint to CPU, no-op in most emulators)
- **CPUID brand-string tail**: читать leaf 0x80000002..04, проверять на характерные подстроки "QEMU", "Hyper"
- **CLI flag `--aggressive-anti-vm`**: opt-in включение CPUID hypervisor check (disabled в default из-за false-positives на Windows 11 VBS)

### 📋 2. Scattered key composition *(средний, высокая сложность)*
Вместо вычисления всего table key в entry stub, распылить компоненты
по первым N handlers. Каждый handler применяет один шаг к key slot
(`[rsp + key_disp]`). Reverser увидит корректный ключ только после
symbolic execution первых N dispatches — static extraction невозможно.

Формула: эффективный ключ при dispatch i = `composition(entry_seed,
{step[0], step[1], ..., step[min(i, N)-1]})`. Таблица encrypted в
build-time с финальной композицией. Первые N dispatches дают
неправильные targets — для них нужны специальные "burn-in" bytecode
инструкции, которые выполняют реальную работу, но чей handler id
совпадает со СТАРТОВЫМ значением key и постепенно доходит до
финального.

### 📋 3. Native handler expansion *(низкий)*
Добавить покрытие generic лифтинга для:
- `shl/shr/sar` с рег-операндами
- `imul` r/m64, r64, imm
- `cmov*` семейство
- Расширенные bit-ops (`bt`, `bts`, `btr`)

### 📋 4. Инфраструктура тестирования *(низкий)*
- Smoke-тест, проверяющий что в выходном бинаре реально присутствуют patterns: XOR handler table, XOR vflags scramble, рандомизированный reg mapping
- Diff-тест двух билдов одного input'а: должны отличаться handler permutation, vflags_key, vflags_rol, XOR keys, reg order, section names, packer key
- Fuzz-style стресс сотни input'ов × full pipeline

---

## Gap vs коммерческие протекторы (VMProtect / Themida)

Субъективная оценка сложности max-protected билда: **50–65** против среднего реверсера,
**65–75** против экспертного с symbolic execution. VMProtect/Themida — ~**70–85**. Дельта
в ~10–15 пунктов объясняется конкретными отсутствующими примитивами. Ниже — долгий
roadmap того, что нужно добавить, чтобы сократить разрыв. Все пункты независимые,
можно реализовывать по одному.

### 📋 G1. Virtual CPU с shuffled register file *(высокий, высокая сложность)*
Сейчас VM хранит guest x64 регистры в фиксированных slots на VM-стеке. У VMProtect
каждый регион получает свой **virtual register file**: guest RAX живёт в vreg[7] в
одном регионе, в vreg[2] в другом, и маппинг per-region рандомизируется. Reverser,
вытащивший семантику одного региона, не может автоматически перенести её на другой —
все load/store работают с vreg indices, а не с guest reg names.

Реализация: `VmInstruction` должен оперировать не `x86Reg`, а `VRegId`. В
`VmRuntimeGen::generate()` при каждом вызове строится `reg_map: x86Reg → VRegId` через
shuffle, bytecode emit'ится в терминах VRegId, handler table индексируется по
(opcode, vreg). При возврате в native context (exit-stub) маппинг разворачивается.

### 📋 G2. Nested VM / VM-in-VM *(высокий, очень высокая сложность)*
Выбранные критические handler'ы (load, store, key derivation, integrity check)
сами виртуализируются под второй, более простой VM с независимым bytecode и
handler table. То, что reverser ожидает увидеть как "handler for ADD" — на самом
деле entry во внутреннюю VM с ещё 5-10 dispatch steps.

Реализация: отдельный `InnerVmLifter` с урезанным opcode set (~8 операций),
`InnerVmRuntimeGen` генерит компактный inner dispatcher. Outer VM handler становится
`call inner_vm_entry; ret`. Overhead: +30-50% bytecode size на защищённый регион,
но реверс times умножается на коэффициент inner-VM сложности.

### 📋 G3. Anti-tampering / anti-hooking runtime *(высокий, средняя сложность)*
Runtime-проверки на integrity самого VM-кода и на наличие inline hooks:
- **Self-CRC**: при каждом N-ном dispatch handler считает CRC32 своего собственного
  instruction range (from label start to label end). Checkpoint пишется в obfuscated
  form в key slot. Разница → порча ключа.
- **Import hook detection**: перед критическим API call (CreateFileW, VirtualProtect,
  NtOpenProcess) проверять первые 5 байт функции на наличие `jmp/call rel32` или
  `mov rax, imm64; jmp rax` — признак inline hook от EDR/Frida/Detours.
- **Thread context poisoning**: периодически прогонять `NtQueryInformationThread`
  на свой же TID и сверять `ContextFlags` — трассировщики часто оставляют
  aberrant context bits.
- **Hardware breakpoint sweep**: читать DR0-DR3 через `NtGetContextThread` со
  своим потоком, ожидать 0. Non-zero = hw bp set.
- **Page protection sweep**: проверять что `.text` + VM-секции всё ещё R+X и не
  W — `VirtualQuery` + сравнение с ожидаемым состоянием.

Каждую probe пишем как отдельный `ICheck` по паттерну anti-emulation registry —
просто новый registry `anti_tamper/` со своим `pick_random()`.

### 📋 G4. Bytecode semantic obfuscation *(высокий, средняя сложность)*
Сейчас bytecode линейный: handler_id, operand, handler_id, operand... Reverser
после extraction таблицы handler'ов читает логику как plain asm. VMProtect
разбрасывает по bytecode:
- **Dead opcodes**: handler'ы, которые читают operand, делают вычисление и
  отбрасывают результат. Выглядят неотличимо от реальных.
- **Opaque branches inside bytecode**: `VJCC` с всегда-ложным условием, уводящая
  на мертвую ветку handlers (которая сама корректно завершается — just in case
  reverser пустит всё подряд).
- **Handler id polymorphism**: один и тот же guest opcode emit'ится через 3-5
  разных handler'ов-синонимов (например, `add rax, rbx` может стать `ADD_A`,
  `ADD_B_via_NEG_SUB`, `ADD_C_via_LEA`). Каждый handler — валидная реализация,
  но выбор per-instruction рандомизирован.
- **Bytecode encryption с rolling key**: каждый handler XOR'ит следующий
  opcode byte ключом, зависящим от своего handler_id. Static decode невозможен —
  только трассировкой.

### 📋 G5. VM handler call graph obfuscation *(средний, средняя сложность)*
Сейчас dispatcher — один `jmp [table + handler_id*8]`. Добавить:
- **Trampolined dispatch**: dispatcher jump'ает на trampoline region, который
  сам через MBA-производный offset прыгает к handler. 2 уровня indirection.
- **Flattened handler bodies**: каждый handler проходит через CFF mini-dispatcher
  внутри себя. Реверсер видит не "ADD handler", а "9-block state machine".
- **Handler bodies interleaved**: handler A{1..5} и handler B{1..5} переплетены
  в памяти с branches между собой — физическая непрерывность handler body
  разрушена.

### 📋 G6. Symbolic-execution hardening *(высокий, очень высокая сложность)*
Targeted против Triton/Miasm/angr — добавляем конструкции, которые взрывают
constraint solver:
- **Hash-based opaque predicates**: `if (sha1(secret_buffer)[0] == 0x4A) do_work();`
  где `do_work` — реальная логика, а `else` — fake. Sha1 внутри constraint'а —
  SMT solver не справится за разумное время.
- **Memory-dependent control flow**: чтение из [rsp + f(handler_id)] где f
  зависит от значений, которые установятся только при корректном прогоне. Symbolic
  engine не может рассуждать о точном значении без конкретизации стека.
- **Loop-based key schedule**: ключ handler table derivation через 64-итерации
  PBKDF2-like chain. Статически unrollable за 64 шага, но symbolic state
  становится неуправляемым.

### 📋 G7. VM stack layout randomization *(средний, низкая сложность)*
Сейчас layout VM-стека фиксирован: `[rsp+0] = saved_rax`, `[rsp+8] = saved_rbx`,
... `[rsp+key_disp] = table_key`. Permutate per-region: каждый билд решает,
в каком slot живёт какой guest reg и в каком — key. Выигрыш малый, но дёшево.

---

## Packer strengthening *(высокий приоритет)*

Packer субъективно самое слабое звено. Сейчас: multi-section XOR с 256-байтным
ключом, indexed через `dl`, IAT wipe, stolen bytes, inline anti-debug через PEB.
Быстро разворачивается тем же Unicorn'ом или даже ручным IDA trace до entry.
План усиления:

### 📋 P1. Замена XOR на stream cipher *(средний)*
XOR с 256-байт ключом восстанавливается за секунды через known-plaintext attack
(первые байты `.text` часто содержат известные паттерны — `48 89 5C 24` prolog,
`C3` ret). Замена:
- **ChaCha20 inline**: ~80 строк ассемблера, key 256 бит, nonce из PEB.ImageBase.
- **RC4 как компромисс**: ~20 строк, key schedule 256 итераций — быстрее
  ChaCha20, слабее криптографически, но всё равно kills known-plaintext на
  entire `.text`.

### 📋 P2. Multi-layer unpacking *(высокий)*
Сейчас один проход XOR → всё расшифровано. VMProtect делает 3-5 слоёв: каждый
слой распаковывает следующий. Layer 1 раскрывает layer 2 stub в куче, который
распаковывает layer 3... Reverser должен пройти все слои trace'ом. Реализация:
layer N в момент распаковки layer N+1 сам себя стирает (`VirtualProtect` +
memset).

### 📋 P3. Entry stub как VM regions *(высокий)*
Весь entry-stub (anti-debug, key derivation, decrypt loop) сам виртуализируется
через существующую VM. Сейчас packer и VM — два разных engine; если packer
entry-stub прогнать через `VirtualizationPass`, получается рекурсивная защита:
packer обеспечивает secrecy на диске, VM обеспечивает difficulty reverse'а
самой распаковки.

### 📋 P4. TLS callback как secondary entry *(средний)*
Entry point в packed PE сейчас один — наш stub. Добавить TLS callback, который
выполняется ДО entry point'а и делает initial anti-debug check + часть key
derivation. Reverser, ставящий bp на entry, пропускает TLS. Overhead: один
extra section `.tls`, TLS directory в PE header.

### 📋 P5. Import protection с API hashing *(высокий)*
Сейчас packer wipe'ает IAT и восстанавливает её в entry stub через
`LoadLibrary` + `GetProcAddress` по имени. Имена лежат plain в packed blob.
Замена: каждая функция хранится как DJB2/FNV-1a хэш её имени, resolver
итерирует export table kernel32/ntdll и сравнивает хэши. `strings` на packed
бинаре не показывает `CreateFileW`, `VirtualAlloc` и т.д.

### 📋 P6. Control-flow integrity в decrypt loop *(низкий)*
Decrypt loop сейчас простой `dec rcx; jnz`. Обернуть тело loop'а в mini-VM
из 3-5 handler'ов, чтобы static patching ("просто NOP'ни decrypt") не работал —
handler table encrypted и завязана на промежуточные состояния.

### 📋 P7. Anti-dump через header stripping *(средний)*
После распаковки packer стирает свой собственный PE header (первые 0x1000 байт
от `ImageBase`), делает section table неконсистентной. Процесс-дамп через Scylla
получает валидный IAT rebuild, но corrupted headers → дамп нужно руками
ремонтировать. Делается одной `VirtualProtect` + memset в entry stub после
unpacking.

### 📋 P8. Guard pages вокруг cold critical data *(низкий, ограниченная применимость)*
Key stream, integrity checkpoints, packer unwrap metadata окружены
`PAGE_GUARD`. Случайный memory read при dump'е через Scylla/PE-sieve попадает
в guard → exception → наш VEH корруптит ключ.

**ВАЖНО — ограничения, которые определяют применимость:**
- Каждое обращение к guarded странице = `STATUS_GUARD_PAGE_VIOLATION`,
  OS конвертит в continuable exception, VEH restoring protect → **5-20 μs
  per access**. Абсолютно неприемлемо для hot path (VM dispatch, bytecode
  stream, per-handler data).
- EDR/debugger VEH часто регистрируются раньше нашего и перехватывают
  guard exception первыми. Это не столько защита от dump, сколько
  **detection signal**: если guard не сработал как ожидалось → значит
  VEH скомпрометирован → корруптим key.
- Применимо только для **cold критичных данных**: packer key stream
  (один touch при unpacking), integrity checkpoints (раз в N dispatches),
  handler table pointer lookup table (кэшируемая). Hot paths — исключены.
- False-positive risk: некоторые AV/EDR помечают guard page usage как
  suspicious. Нужна валидация на реальных AV setups перед включением.

---

## String protection *(высокий приоритет)*

Текущее состояние: `.rdata` шифруется packer'ом на диске, но после распаковки
ВСЕ строки лежат plain в памяти процесса. `ProcessHacker` / `Scylla` / process
dump мгновенно достают URL'ы, API endpoints, error messages, ключи валидации,
hardcoded credentials. Это огромная leak'овая поверхность — fix обязательный.

Многоуровневая архитектура: SDK macro (opt-in) + binary pass (для non-annotated)
+ VM-protected decoder (самый сильный слой).

### 📋 S1. SDK macro `MX_STR("...")` *(низкий, высокая ценность)*
Constexpr XOR с compile-time ключом, разворачивается в inline stack buffer,
конструируется байт-за-байтом при обращении, zero'ится при возврате caller'а
через `MX_STR_END()` либо RAII scope guard. Pattern — ADVObfuscator.

```cpp
auto s = MX_STR("https://license.example.com/check"); // returns scoped_str
HTTPGet(s.c_str());
// at scope exit: memset(buffer, 0, len)
```

В `.rdata` не попадает ни одного байта исходной строки — compiler embeds XOR'ed
байты как immediates в instruction stream. Key derives from `(file_hash, line,
counter)` чтобы две одинаковые строки в разных местах имели разные cipher'ы.
Wide-string вариант `MX_WSTR(L"...")`.

### 📋 S2. Binary-level `.rdata` string transform pass *(средний)*
Для unannotated strings (RTTI, std::exception msgs, third-party libs, логи):
1. Scan `.rdata` на printable ASCII/UTF-16 runs ≥ 4 chars, filter false-positives
   (export names, section names, COFF metadata).
2. Build XREF table: для каждой найденной строки — список `LEA rip+disp32` в
   `.text` которые на неё ссылаются.
3. Заменить XREF'ы на `call __mx_str_decrypt(string_id)` (relocated).
4. Исходные байты в `.rdata` перезаписать encrypted'ом.
5. `__mx_str_decrypt` возвращает указатель на TLS buffer с ephemeral decoded
   копией; caller должен вызвать `__mx_str_release(ptr)` либо полагаться на
   auto-wipe при следующем вызове decryptor'а (LRU в TLS slot pool).

Сложность средняя: XREF discovery надо делать аккуратно (jump tables, switch
tables, vtable data false-positives). MVP версия игнорирует ambiguous refs.

### 📋 S3. Per-string unique key + ephemeral lifetime *(низкий, сверху S1+S2)*
Не один глобальный XOR ключ. Derive per-string через
`key = f(string_id, TEB->Tid, GetTickCount() >> 10)` либо через key schedule
в entry stub. Выигрыш: даже если dump ловит один decryptor call, ключ не
универсален — остальные строки не раскрываются. Memset wipe сразу после
caller возврата → dump снимает максимум одну строку в моменте.

### 📋 S4. Decryptor в VM-protected регионе *(средний, сверху S1/S2)*
`__mx_str_decrypt` сам обернут в `MX_VM_BEGIN/END`. Reverser, который хочет
статически понять как строки расшифровываются, сначала должен сломать VM.
Естественно комбинируется с P3 (packer stub в VM). Overhead: decryption
становится ~50-100× медленнее, но строки обычно на cold paths
(init, error reporting, network URLs) где это незаметно.

### 📋 S5. Scan-resistant format: split across sections *(низкий, polish)*
String bytes разбросаны по нескольким non-`.rdata` секциям (`.bss` с init из
entry, `.data` padding, hidden payload в overlay). Reassembly происходит в
runtime decoder'е. `strings` и entropy-based scanners видят fragments, не
целостные строки. Overhead: одна LEA + одна `memcpy` на access.

### 📋 S6. Compiler-generated strings (RTTI, exceptions) *(низкий, сложный)*
MSVC embeds class names в RTTI (`.?AVFoo@@`), exception messages в
`std::exception::what()`. Часть decorated symbol'ов невозможно убрать без
отключения RTTI (`/GR-`), что ломает `dynamic_cast` и typeid. Частичное
решение: для классов без RTTI-dependent кода добавить `#pragma` вывод в
отдельную секцию, которую packer stream-cipher'ит + S2 pass проходит по XREF.
Нерешаемые остатки — документировать как known leak и рекомендовать
`/GR-` для release builds.

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

## Отклонённые идеи (не возвращаться)

- **Delta-trick для ASLR-совместимого ImageBase key**:
  `BaseForKey = RuntimeBase - (RuntimeBase - PreferredBase)`. Формула
  сокращается до `PreferredBase`, который известен статически из PE
  заголовка, поэтому "обфускация" тривиально реверсится. Фундаментально
  нельзя сделать ключ зависящим только от ASLR-state: если ключ должен
  быть ИДЕНТИЧНЫМ у всех запусков бинаря, он должен зависеть только от
  build-time-known данных. Если ОТ runtime-state — то надо SHIPping
  шифротекст с per-запуск перекриптовкой, что дорого и не даёт ничего.
  → Используем ImageBase key только когда packer disables ASLR.

- **Rolling key для handler table decryption**:
  Смешение потокового шифра с ассоциативной таблицей. Rolling key
  предполагает линейный порядок доступа (каждый байт декриптуется один
  раз), а handler table читается в произвольном порядке с multiple
  hits на один entry. Нельзя согласовать не потеряв либо корректность,
  либо обфускацию. → Если нужно "не оставлять ключ в памяти" — делать
  scattered key composition (пункт 3 roadmap'а), а не rolling.

- **Decrypt handler table in-place при первом dispatch**:
  После первого использования таблица становится plaintext в памяти.
  Любой дамп после первого VM вызова вскрывает dispatch map. Обфускация
  только против ПРЕДВАРИТЕЛЬНОГО статического анализа, не против
  dynamic analysis. Наша цель — обе формы, поэтому in-place decrypt
  не подходит.
