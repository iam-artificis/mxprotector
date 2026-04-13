# MxProtector Roadmap

Forward-looking work list. Completed items live in `git log`, not here.

Legend:

| Marker | Meaning |
|---|---|
| 📋 | Planned |
| ⏳ | In progress |
| ❌ | Rejected (see "Rejected ideas" section) |

---

## Sequential Implementation Plan

Do these in order. Each item is a one-liner; see the detailed sections
below for the full spec.

1. ⏳ **S3 — ephemeral per-session string keys.** Derive XOR key per string
   from `f(string_id, TEB.Tid, GetTickCount() >> 10)` so a memory dump
   captures at most one decrypted string at a time. § "String protection" → S3.
2. 📋 **DLL packer.** DllMain-aware stub variant. Today `PackerPass`
   auto-skips on `.dll` (see `STABILITY.md` §6) and the result is
   mutation/obfuscation/VM/CFF only. A DllMain stub unlocks full `-l strong`
   on DLLs: on `DLL_PROCESS_ATTACH` run the decrypt loop then call the real
   DllMain; forward other reasons verbatim; preserve export table + IAT
   across unpacking. § "Packer strengthening" (new subsection to add when
   work starts).
3. 📋 **SYS packer.** DriverEntry stub variant. Same shape as DLL but for
   kernel-mode entry ABI. Blocked on test-signing infrastructure, not on
   code. Lower priority than DLL.
4. 📋 **Packer strengthening — P1 ChaCha20 stream cipher.** Replaces the
   256-byte XOR key in the packer. Largest single uplift against
   static unpackers. § "Packer strengthening" → P1.
5. 📋 **Packer strengthening — P3 VM-protected entry stub.** Entry stub
   (anti-debug, key derivation, decrypt loop) itself virtualized through
   the existing VM engine. § "Packer strengthening" → P3.
6. 📋 **Packer strengthening — P5 import hashing.** Replace plain
   `LoadLibrary` + `GetProcAddress(name)` in the packer stub with DJB2/FNV-1a
   hash resolution from kernel32/ntdll export tables. Kills `strings` on
   packed binaries. § "Packer strengthening" → P5.
7. 📋 **Packer strengthening — P2 / P4 / P6 / P7 / P8.** Multi-layer
    unpacking, TLS-callback secondary entry, CFI in decrypt loop,
    header stripping, guard pages. Lower priority polish. § "Packer
    strengthening".
8. 📋 **VM strengthening — G2 nested VM.** Inner VM for critical handlers
    (load, store, key derivation). § "Gap vs коммерческие" → G2.
9. 📋 **VM strengthening — G4 bytecode semantic obfuscation.** Dead
    opcodes, opaque bytecode branches, handler id polymorphism, rolling
    key per handler. § "Gap vs коммерческие" → G4.
10. 📋 **VM strengthening — G5 handler call graph obfuscation.**
    Trampolined dispatch, handler-body flattening, handler-body
    interleaving. § "Gap vs коммерческие" → G5.
11. 📋 **G6 symbolic-execution hardening.** Hash-based opaque predicates,
    memory-dependent control flow, loop-based key schedules. Hardest,
    lowest on the list. § "Gap vs коммерческие" → G6.
12. 📋 **G3 extensions — extra anti-tamper checks.** Thread context
    poisoning (`NtQueryInformationThread` self-inspect), guard-page
    VEH-integrity trap. Independent of the main chain, can slot in any
    time.

---

## Gap vs коммерческие протекторы (VMProtect / Themida)

Оставшиеся G-пункты. Каждый независимый, реализуемы по одному.

### 📋 G2. Nested VM / VM-in-VM *(высокий, очень высокая сложность)*
Выбранные критические handler'ы (load, store, key derivation, integrity check)
сами виртуализируются под второй, более простой VM с независимым bytecode и
handler table. То, что reverser ожидает увидеть как "handler for ADD" — на самом
деле entry во внутреннюю VM с ещё 5-10 dispatch steps.

Реализация: отдельный `InnerVmLifter` с урезанным opcode set (~8 операций),
`InnerVmRuntimeGen` генерит компактный inner dispatcher. Outer VM handler становится
`call inner_vm_entry; ret`. Overhead: +30-50% bytecode size на защищённый регион,
но реверс times умножается на коэффициент inner-VM сложности.

### 📋 G4. Bytecode semantic obfuscation *(высокий, средняя сложность)*
Сейчас bytecode линейный: handler_id, operand, handler_id, operand... Reverser
после extraction таблицы handler'ов читает логику как plain asm. VMProtect
разбрасывает по bytecode:
- **Dead opcodes**: handler'ы, которые читают operand, делают вычисление и
  отбрасывают результат. Выглядят неотличимо от реальных
- **Opaque branches inside bytecode**: `VJCC` с всегда-ложным условием, уводящая
  на мертвую ветку handlers (которая сама корректно завершается)
- **Handler id polymorphism**: один и тот же guest opcode emit'ится через 3-5
  разных handler'ов-синонимов (`add rax, rbx` → `ADD_A` / `ADD_B_via_NEG_SUB` /
  `ADD_C_via_LEA`). Каждый — валидная реализация, выбор per-instruction
  рандомизирован. Расширяет существующий G1 specialization механизм
- **Bytecode encryption с rolling key per-handler**: каждый handler XOR'ит
  следующий opcode byte ключом зависящим от своего handler_id. Static decode
  невозможен — только трассировкой

### 📋 G5. VM handler call graph obfuscation *(средний, средняя сложность)*
Сейчас dispatcher — один `jmp [table + handler_id*8]`. Добавить:
- **Trampolined dispatch**: dispatcher jump'ает на trampoline region, который
  сам через MBA-производный offset прыгает к handler. 2 уровня indirection
- **Flattened handler bodies**: каждый handler проходит через CFF mini-dispatcher
  внутри себя. Реверсер видит не "ADD handler", а "9-block state machine"
- **Handler bodies interleaved**: handler A{1..5} и handler B{1..5} переплетены
  в памяти с branches между собой — физическая непрерывность handler body
  разрушена

### 📋 G6. Symbolic-execution hardening *(высокий, очень высокая сложность)*
Targeted против Triton/Miasm/angr — добавляем конструкции, которые взрывают
constraint solver:
- **Hash-based opaque predicates**: `if (sha1(secret_buffer)[0] == 0x4A) do_work();`
  — sha1 внутри constraint'а, SMT solver не справится за разумное время
- **Memory-dependent control flow**: чтение из [rsp + f(handler_id)] где f
  зависит от значений, установленных только при корректном прогоне. Symbolic
  engine не может рассуждать без конкретизации стека
- **Loop-based key schedule**: ключ handler table derivation через 64-итерации
  PBKDF2-like chain. Статически unrollable за 64 шага, но symbolic state
  становится неуправляемым

---

## Packer strengthening *(высокий приоритет)*

Packer субъективно самое слабое звено: multi-section XOR с 256-байтным
ключом, быстро разворачивается Unicorn'ом. План усиления:

### 📋 P1. Замена XOR на stream cipher *(средний)*
XOR с 256-байт ключом восстанавливается за секунды через known-plaintext
attack (первые байты `.text` часто содержат предсказуемые patterns). Замена:
- **ChaCha20 inline**: ~80 строк ассемблера, key 256 бит, nonce из PEB.ImageBase
- **RC4 как компромисс**: ~20 строк, key schedule 256 итераций, слабее
  криптографически, но всё равно kills known-plaintext attack

### 📋 P2. Multi-layer unpacking *(высокий)*
VMProtect делает 3-5 слоёв: layer N раскрывает layer N+1, затем сам себя
стирает (`VirtualProtect` + memset). Reverser должен пройти все слои trace'ом.

### 📋 P3. Entry stub как VM regions *(высокий)*
Packer entry-stub (anti-debug, key derivation, decrypt loop) сам
виртуализируется через существующий VM engine. Рекурсивная защита: packer
обеспечивает secrecy на диске, VM обеспечивает difficulty reverse'а самой
распаковки.

### 📋 P4. TLS callback как secondary entry *(средний)*
Entry point сейчас один — наш stub. TLS callback выполняется ДО entry point'а
и делает initial anti-debug check + часть key derivation. Reverser, ставящий
bp на entry, пропускает TLS.

### 📋 P5. Import protection с API hashing *(высокий)*
Packer сейчас restore'ит IAT через `LoadLibrary` + `GetProcAddress` по имени.
Имена лежат plain в packed blob. Замена: функции хранятся как DJB2/FNV-1a
хэши, resolver итерирует export table kernel32/ntdll и сравнивает. `strings`
на packed бинаре не показывает `CreateFileW`, `VirtualAlloc` и т.д.

### 📋 P6. Control-flow integrity в decrypt loop *(низкий)*
Decrypt loop сейчас простой `dec rcx; jnz`. Обернуть тело loop'а в mini-VM
из 3-5 handler'ов, чтобы static patching ("просто NOP decrypt") не работал.

### 📋 P7. Anti-dump через header stripping *(средний)*
После распаковки packer стирает свой собственный PE header (первые 0x1000
байт от ImageBase). Процесс-дамп через Scylla получает corrupted headers,
дамп нужно руками ремонтировать.

### 📋 P8. Guard pages вокруг cold critical data *(низкий, ограниченная применимость)*
Key stream, integrity checkpoints, packer unwrap metadata окружены
`PAGE_GUARD`. Hot paths исключены из-за 5-20 μs per access overhead.
Detection signal, не защита от dump.

---

## String protection

### ⏳ S2. Binary-level `.rdata` string transform pass *(средний, высокая ценность)*
Для unannotated strings (RTTI, std::exception msgs, third-party libs, логи):

1. ✅ Scan `.rdata` на printable ASCII runs ≥ 4 chars, filter false-positives.
   `string_scanner.{hpp,cpp}` + unit tests.
2. ✅ Build XREF table: для каждой найденной строки — список `LEA rip+disp32`
   в `.text`. `string_xref_finder.{hpp,cpp}` + unit tests (Zydis-based).
3. ✅ Per-string XOR encryptor: `string_encryptor.{hpp,cpp}` + unit tests.
4. ✅ `mx_str_get` decryptor + per-xref trampoline codegen:
   `string_decryptor_codegen.{hpp,cpp}` + byte-level unit tests.
   Layout: `[mx_str_get (~66B)] [trampolines (~40B each)] [descriptor
   table (8B per string)] [encrypted pool]`.
5. ✅ **Orchestrator pass** (`StringProtectionPass`): собирает `.mxstr`
   секцию из вышеперечисленных блоков, патчит две rip+disp32 ссылки
   внутри `mx_str_get` и call rel32 внутри каждого трамплина, переписывает
   LEA xref'ы на `call trampoline` + NOP padding, регистрируется в
   PassManager, консьюмит `--strings=stub`.
6. ✅ Подключение `--strings=vm`: XOR decrypt loop lifted via
   `VmLifter` + `VmRuntimeGenerator`, VM blob embedded in `.mxstr`,
   loop body overwritten with `call vm_entry` + NOP pad. S2c's inner
   VM passes `skip_anti_tamper_checks=true` — `page_protection_sweep`
   assumes the packer revoked WRITE on the VM section, but `.mxstr`
   stays R+W+X on purpose for the in-place XOR decrypt.

Сложность: XREF discovery надо делать аккуратно (jump tables, switch
tables, vtable data false-positives). MVP версия игнорирует ambiguous
refs — только exact `LEA reg, [rip+disp32]` с dest_rva == string_start.

**Thread safety**: текущий XOR loop не атомарен. Два потока, входящие
в `mx_str_get` для одного string_id до того, как sticky flag установлен,
могут сделать double-XOR обратно в ciphertext. Fix (S3): `lock cmpxchg`
claim на flag byte.

### 📋 S3. Per-string unique key + ephemeral lifetime *(низкий, сверху S2)*
Derive key per-string через `f(string_id, TEB->Tid, GetTickCount() >> 10)`.
Dump ловит максимум одну строку в моменте.

### 📋 S4. Decryptor в VM-protected регионе *(средний, сверху S2)*
`__mx_str_decrypt` сам обернут в `MX_VM_BEGIN/END`. Комбинируется с P3.
Overhead ~50-100× slowdown на decryption, но strings обычно на cold paths.

### 📋 S5. Scan-resistant format: split across sections *(низкий, polish)*
String bytes разбросаны по нескольким non-`.rdata` секциям. Reassembly в
runtime decoder'е. `strings` и entropy scanners видят fragments.

### 📋 S6. Compiler-generated strings (RTTI, exceptions) *(низкий, сложный)*
MSVC embeds class names в RTTI, exception messages в `std::exception::what()`.
Частичное решение: `#pragma` вывод RTTI в отдельную секцию, packer
stream-cipher'ит, S2 pass проходит по XREF. Нерешаемые остатки — документировать
как known leak и рекомендовать `/GR-` для release builds.

---

## Cross-platform plan

Две ортогональных оси: **container** (PE / ELF / Mach-O) и **architecture**
(x64 / arm64 / cortex-m). Foundation interfaces (TargetInfo, IBinaryImage,
ArchInfo, ICodeEmitter, IVmBackend) уже объявлены.

### Container axis

Целевая поддержка:
1. **Windows PE** — единственный сейчас, полный pipeline
2. **Linux ELF** — primary secondary target (embedded Linux, Android, desktop)
3. **macOS Mach-O** — tertiary (Apple Silicon)

**📋 Phase 2 — PE tucks under the interface:**
- `PeImage` implements `IBinaryImage`
- `PeParser` / `PeBuilder` → `IBinaryImageParser` / `IBinaryImageBuilder`
- `ProtectionContext::image_` перетипизируется в `unique_ptr<IBinaryImage>`

**📋 Phase 3 — ELF parser/builder:**
- `ElfImage`, `ElfParser`, `ElfBuilder` в `src/builder/elf/`
- Детект контейнера по magic: `MZ` → PE, `\x7fELF` → ELF
- `TargetInfo` заполняется из парсера

**📋 Phase 4 — Target-specific passes:**
- Linux-версия packer: ELF-совместимый decrypt stub, syscall-based init
- Linux анти-отладка: ptrace checks, `/proc/self/status:TracerPid`
- macOS Mach-O parser + ptrace/sysctl анти-debug

### Architecture axis

1. **x86-64** — текущая, полный pipeline
2. **ARMv8-A (arm64)** — следующий шаг после ELF container backend
3. **Cortex-M** — experimental, только после v8-A и если есть реальный спрос
4. **Cortex-R** — не в scope

**📋 Phase 3 arch — arm64 VM backend:**
- `Arm64CodeEmitter : ICodeEmitter` — A64 instruction encoding, 31 GPRs
- `Arm64VmBackend : IVmBackend`:
  - 31-slot VM context вместо 16
  - Flag handling через MRS/MSR NZCV или computed-predicate в GPRs
  - Handler dispatch через ADR + LDR + BR table
  - Stream cipher через LDR/LDR/EOR/STR (4-byte unit)
- Arm64-specific mutation rules

**📋 Phase 4 arch — Linux/Android arm64 target passes:**
- `LinuxArm64PackerPass`: ELF stub на arm64, ptrace-based anti-debug
- Android Runtime hook checks (Frida, Xposed)

**📋 Phase 5 arch — experimental Cortex-M (optional):**
- Thumb-2 only encoding, ограниченный набор инструкций
- Нет MMU → ImageBase key бесполезен
- Нет dynamic linker → static import resolution
- Custom container format (raw binary + manifest)

### Непортируемые фичи

| Фича | Ограничение | Примечание |
|---|---|---|
| PE header erasure, PEB anti-debug, IAT destruction | Windows PE | PE-версия `PackerPass` |
| vEFLAGS через RFLAGS scramble | x86-64 | Arm64 backend: NZCV-based подход |
| Rolling-key stream cipher через pushfq/popfq | x86-64 | Arm64: LDP/STP + EOR |
| ptrace-based anti-debug | Linux/Android | `LinuxPackerPass` |
| `sysctl` KERN_PROC anti-debug | macOS | `MacOSPackerPass` |
| TrustZone-M anti-tamper | Cortex-M33 | Experimental, нужна hardware |

---

## Другие направления

### 📋 Расширенная инфраструктура тестирования *(низкий)*
- **Behavior tests для HW BP / Page Protection / Import Hook**: требуют
  либо in-process execution of emitted bytes (VirtualAlloc + unsafe rsp
  manipulation + SEH), либо реальных debugger'ов/hook'ов в test process.
  Для Self-CRC мы сделали build-time logical verification; syscall-based
  checks требуют mock NTDLL environment или DLL injection harness
- **Diff-тест** двух builds одного input'а: должны отличаться handler
  permutation, vflags_key, vflags_rol, XOR keys, reg order, section names,
  packer key, specialized handler selection, extra_pad_slots, anti-tamper pick
- **Fuzz-style стресс** сотни input'ов × full pipeline

### 📋 Anti-emulation pool (остатки) *(низкий-средний)*
- **FPU quirks**: x87 precision-control behaviors, rounding edge cases
- **Scheduler timing**: timing delta across `pause` instruction
- **CPUID brand-string tail**: leaf 0x80000002..04, характерные подстроки
  "QEMU", "Hyper"
- **CLI flag `--aggressive-anti-vm`**: opt-in enable CPUID hypervisor check
  (disabled по умолчанию из-за false-positives на Windows 11 VBS/Hyper-V/WSL2)

### 📋 Scattered key composition *(средний, высокая сложность)*
Вместо вычисления всего handler table key в entry stub, распылить компоненты
по первым N handlers. Каждый handler применяет один шаг к key slot. Reverser
увидит корректный ключ только после symbolic execution первых N dispatches —
static extraction невозможно.

### 📋 Native handler expansion *(низкий)*
Покрытие generic лифтинга для:
- `shl/shr/sar` с рег-операндами
- `imul` r/m64, r64, imm (сейчас есть только r-r)
- `cmov*` семейство
- Расширенные bit-ops (`bt`, `bts`, `btr`)

### 📋 Refactor: unified PEB walker *(низкий, code hygiene)*
`hells_gate_resolver.cpp`, `import_hook_check.cpp` содержат почти идентичные
PEB walk + PE export scan блоки (~130 байт каждый). Factor out общий helper
`emit_ntdll_export_find(e, target_hash)` который оставляет function address
в `rdi`. Каждый check делает свою post-processing. Упрощает добавление
будущих checks, использующих NTDLL resolution.

---

## Вне scope

- Cross-process injection stub
- .NET / managed target support
- Сетевая лицензия / DRM-хуки
- JIT-compiled stub (runtime-assembled stub code)

---

## Отклонённые идеи (не возвращаться)

### Delta-trick для ASLR-совместимого ImageBase key
`BaseForKey = RuntimeBase - (RuntimeBase - PreferredBase)`. Формула сокращается
до `PreferredBase`, известного статически из PE заголовка. Фундаментально нельзя
сделать ключ зависящим только от ASLR-state: если ключ должен быть идентичным
у всех запусков бинаря, он должен зависеть только от build-time-known данных.
→ ImageBase key используем только когда packer disables ASLR.

### Rolling key для handler table decryption
Rolling key предполагает линейный порядок доступа, handler table читается в
произвольном порядке с multiple hits на один entry. Несогласованно.
→ Для "не оставлять ключ в памяти" делаем scattered key composition.

### Decrypt handler table in-place при первом dispatch
После первого использования таблица становится plaintext в памяти. Dump
после первого VM вызова вскрывает dispatch map. Обфускация только против
предварительного static analysis, не против dynamic. Наша цель — обе формы.

### AC flag fidelity (EFLAGS bit 18 round-trip)
Setting EFLAGS.AC=1 в user mode на Windows arms alignment-check trap.
Любой последующий unaligned access в CRT/vectorised memcpy/exception unwind
raises #AC и крашит protected binary. Bisect empirically: forced-zero
variant всё равно крашил ~25% builds; удаление `or rax, 0x40000` (не setting
AC bit) → 40/40 OK. Catch задокументирован в `check_registry.cpp`.
На Linux ELF можно возвращать (`CR0.AM` там cleared), но только в
Linux-only registry.

### SALC / ICEBP undocumented opcodes для anti-emulation
Opcodes `D6` (SALC) и `F1` (ICEBP) invalid в long mode, raises #UD на
реальном x64. Катится только для 32-bit Windows targets.

### Hell's Gate syscalls как "замена" packer'у
EncryptionPass + stub_main loader (ChaCha20/AES, manual import resolver,
Hell's Gate SSN resolution) был попыткой построить "strong" crypt layer
параллельно packer'у. Loader никогда не был встроен в output PE → любой билд
с encryption ломался. Удалён полностью.
→ Если нужен anti-EDR режим с прямыми syscall'ами — добавлять как **опцию
поверх** packer'а, не альтернативную вселенную. Уже есть base infrastructure
(G3.2 runtime Hell's Gate), можно переиспользовать.
