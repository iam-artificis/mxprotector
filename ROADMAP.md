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

1. ⏳ **DLL packer.** DllMain-aware stub variant. Today `PackerPass`
   auto-skips on `.dll` (see `STABILITY.md` §6) and the result is
   mutation/obfuscation/VM/CFF only. A DllMain stub unlocks full `-l strong`
   on DLLs: on `DLL_PROCESS_ATTACH` run the decrypt loop then call the real
   DllMain; forward other reasons verbatim; preserve export table + IAT
   across unpacking. § "Packer strengthening" (new subsection to add when
   work starts).
2. 📋 **SYS packer.** DriverEntry stub variant. Same shape as DLL but for
   kernel-mode entry ABI. Blocked on test-signing infrastructure, not on
   code. Lower priority than DLL.
3. 📋 **Packer strengthening — P5 import hashing.** Replace plain
   `LoadLibrary` + `GetProcAddress(name)` in the packer stub with DJB2/FNV-1a
   hash resolution from kernel32/ntdll export tables. Kills `strings` on
   packed binaries. § "Packer strengthening" → P5.
4. 📋 **Packer strengthening — P2 / P4 / P6 / P7 / P8.** Multi-layer
    unpacking, TLS-callback secondary entry, CFI in decrypt loop,
    header stripping, guard pages. Lower priority polish. § "Packer
    strengthening".
5. ⏳ **VM strengthening — G2 nested VM.** Initial scope shipped —
    inner VM for `add_rr` / `sub_rr` / `xor_rr` handlers: zero-operand
    threaded interpreter, 64-byte runtime (dispatcher + 4 handlers +
    handler table), per-op V2 variant. Remaining: расширенная ISA
    (10–12 opcode'ов, scratch vflags slot), остальные хэндлеры
    (mov/and/or/not/neg/ri32/vjcc), per-build randomization.
    § "Gap vs коммерческие" → G2-extended.
6. 📋 **VM strengthening — G4 bytecode semantic obfuscation (remainder).**
    Handler id polymorphism already shipped (8 canonical ops × 2
    variants each). Still open: dead opcodes via dedicated
    flag-preserving handlers, opaque bytecode branches, rolling key
    per handler. § "Gap vs коммерческие" → G4.
7. 📋 **VM strengthening — G5 handler call graph obfuscation.**
    Trampolined dispatch, handler-body flattening, handler-body
    interleaving. § "Gap vs коммерческие" → G5.
8. 📋 **G6 symbolic-execution hardening.** Hash-based opaque predicates,
    memory-dependent control flow, loop-based key schedules. Hardest,
    lowest on the list. § "Gap vs коммерческие" → G6.
9. 📋 **G3 extensions — extra anti-tamper checks.** Thread context
    poisoning (`NtQueryInformationThread` self-inspect), guard-page
    VEH-integrity trap. Independent of the main chain, can slot in any
    time.

---

## Gap vs коммерческие протекторы (VMProtect / Themida)

Оставшиеся G-пункты. Каждый независимый, реализуемы по одному.

### ⏳ G2. Nested VM / VM-in-VM *(initial scope shipped, extended scope 📋)*

Shipped scope: the three register-register ALU handlers (`add_rr`,
`sub_rr`, `xor_rr`) each gained a third variant (`V2`) whose body
hands the arithmetic off to a nested, independently-dispatched
bytecode interpreter.

Design (files: `include/mxprotector/protection/vm/x64/x64_inner_vm.hpp`,
`src/builder/protection/vm/x64/x64_inner_vm.cpp`):

- **Inner ISA — 4 opcodes, zero operands.** `iload_src` (r14 ← [rdi]),
  `iadd_exit` / `isub_exit` / `ixor_exit` ([rsi] ⊙= r14; ret). No
  sentinel byte — the terminal handler's ALU op + `ret` is the exit.
  Lifted bytecodes: `add_rr → [iload_src, iadd_exit]` (2 bytes), same
  shape for sub / xor.
- **64-byte position-independent runtime.** 28-byte dispatcher
  (`lea r13, [rip+ht] → .loop: movzx/inc/mov/movsxd/add/jmp rax`) +
  4 handler bodies (17 bytes) + 3 bytes padding + 16-byte handler
  table of signed int32 offsets relative to the table base. Every
  intra-runtime branch is either a short rel8 back to `.loop` or the
  rip-relative `lea r13`. Zero external patches.
- **r14, not rax, is the inner src register.** The dispatcher loop
  clobbers rax every iteration (opcode fetch → table index → handler
  address). Using rax for iload_src would overwrite it before the
  terminal ALU ever runs. An earlier first-pass bug did exactly this
  and added the handler address to the destination slot — see commit
  history if you need the 48-bit-pointer fiasco as a cautionary tale.
- **Flags propagate via `ret` itself.** The terminal ALU op is the
  last flag-touching instruction before `ret`; `ret` preserves rflags;
  the outer handler's tail dispatch (`emit_vflags_store`) saves them
  straight into `vflags`. No stack push/pop, no dispatcher re-entry
  between ALU and exit. The same trap that killed the G4 dead-opcode
  experiment applies here — any extra flag-clobbering instruction
  between ALU and `ret` corrupts downstream `vjcc`.
- **Outer handler V2 shape.** `emit_handler_alu_rr_nested` emits
  `fetch operand bytes → compute [rsi]/[rdi] → lea r12, [rip+2] → jmp
  2 → <2-byte bc> → call rel32 inner_vm_entry`. The backend collects
  every V2's rel32 patch offset into `inner_vm_call_patches`, emits
  the 64-byte runtime once (16-byte aligned) after all handlers, and
  patches all call sites to point at the dispatcher entry.

Verified against the standard 90× stress (6 VM test apps × 3 strings
modes × 5 runs) at strong level and a maximum-level build of
`test_vm_showcase`, all green.

#### Remaining scope — G2-extended (📋 TODO)

Initial scope (4-opcode terminal-producer ISA, 3 ALU хэндлеров, 1
dispatch step) даёт правильную инфраструктуру — runtime emit, rel32
patch loop, V2 вариант в `variant_count_for` — но покрывает слишком
узкое множество и без depth'а не даёт того ROI, который G2 в принципе
должен обеспечить. Ниже — что нужно, чтобы довести до полноценного
nested VM.

**1. Расширенная ISA (~10–12 opcode'ов).** Терминал-producer схему
заменяет честный threaded interpreter с промежуточными значениями.
Ожидаемый набор:

```
iload_src        r_inner <- [rdi]                    ; src slot value
iload_dst        r_inner <- [rsi]                    ; dst slot value (для ALU rr)
istore_dst       [rsi] <- r_inner                    ; запись результата
ialu_rr  op      r_inner <- r_inner <op> tmp_inner   ; op в byte-операнде
ialu_ri  op imm8 r_inner <- r_inner <op> imm8
ikey_xor imm8    r_inner <- r_inner ^ imm8           ; шаг rolling key
imov_tmp         tmp_inner <- r_inner                ; сохранить промежуточный
iswap            r_inner <-> tmp_inner
iret             возврат во внешний хэндлер; rflags = последний ALU
ibranch imm8     условный переход внутри inner bc по ZF (для vjcc lift'а)
```

Точный набор подбирается по тому, какие outer-хэндлеры лифтим, но
минимум 6–8 opcode'ов необходим — иначе inner VM не даёт ни depth, ни
полиморфизма, ради которых G2 делается.

**2. Раскладка регистров host'а (расширение текущей).** Строго:

- `rsi` — dst slot addr (set by outer);
- `rdi` — src slot addr (set by outer);
- `r12` — inner VPC;
- `r13` — inner handler-table base;
- `r14` — inner "r_inner" (НЕ rax — см. урок #1 ниже);
- `r15` — inner "tmp_inner" *(новое — в initial scope не использовался)*;
- `r11` — outer VPC (ни в коем случае не трогать).

**3. Flag propagation для multi-step ISA.** Текущая схема
(`add [rsi], r14; ret` — терминальный ALU последний flag-producer) не
масштабируется на несколько ALU step'ов: любой промежуточный
flag-producer клобберит rflags до терминала. Варианты:

1. **Terminal-producer (как сейчас).** Последний ALU перед `iret`
   обязан быть flag-producer'ом, все nonterminal ALU до него
   выполняются через `pushfq/popfq` вокруг dispatch step'а. Дороже, но
   универсально.
2. **Scratch vflags slot внутри inner VM.** Inner VM сохраняет флаги в
   отдельный inner-slot после каждой ALU и восстанавливает их перед
   `iret`. Требует `pushfq` ровно 1 раз на хэндлер, не на step.
3. **Отложенная семантика (текущий initial scope).** Inner VM не
   производит guest-ALU промежуточных значений — только терминальный
   хэндлер делает финальный op напрямую по memory operand. Ограничивает
   ширину лифтинга, но дёшево.

Рекомендация: **схема 2**. Её легче расширить на vjcc-лифт и на
полноценный `ialu_ri` без потери гостевых флагов. Схема 3 остаётся как
fast-path для простых случаев.

**4. Outer-handler coverage (кандидаты в порядке ценности).**

| Outer handler | Inner bc (пример) | Статус |
|---|---|---|
| `add_rr`/`sub_rr`/`xor_rr` | `iload_src; iadd_exit`/etc | ✅ shipped |
| `and_rr`/`or_rr` | `iload_src; iload_dst; ialu_rr op; istore_dst; iret` | 📋 |
| `mov_rr` | `iload_src; istore_dst; iret` | 📋 |
| `*_ri32` (add/sub/xor/and/or) | `iload_dst; ialu_ri op imm; istore_dst; iret` | 📋 (зависит от inline imm в inner bc) |
| `not_r` / `neg_r` | `iload_dst; iunary op; istore_dst; iret` | 📋 |
| `vjcc` key derivation | серия `ikey_xor imm8` + `ibranch` | 📋 (высокая ценность — vjcc key самый атакуемый хэндлер) |
| `exit` декриптор / integrity check | длинная серия inner ops | 📋 (максимальный depth, аккуратно с флагами) |

Минимальный целевой scope следующей итерации: все r-r ALU (+and/or),
`mov_rr`, унарные, хотя бы одна `ri32` форма. Это +5–6 outer хэндлеров
поверх текущих 3.

**5. Per-build randomization.** Без этого G2 теряет половину смысла —
reverser один раз разбирает наш runtime и дальше видит его в каждом
билде:

- permuted opcode byte'ы (substitution inside inner ISA);
- shuffled handler table;
- junk в диспетчере (dead byte'ы, alternate encoding `lea r13`);
- опционально — 2–3 разные формы диспетчера (threaded / switch /
  indirect-through-jump-table), выбираемые rng в начале билда.

#### Уроки от initial scope (CRITICAL READ перед расширением)

Всё это проверено опытом, не догадки — не наступайте повторно.

1. **Inner src register ≠ rax.** Диспетчер `movzx eax, byte [r12]; mov
   eax, [r13+rax*4]; movsxd; add rax, r13; jmp rax` клобберит rax
   каждую итерацию. Любой inner opcode, который читает или пишет в
   rax для хранения значения между dispatch step'ами, получит в rax
   адрес следующего хэндлера вместо своего значения. Первая попытка
   именно так и сложила handler address в dst slot → 0x7FF6xxxxxxxx
   повсюду. `r14` для r_inner, `r15` для tmp_inner.

2. **Outer-хэндлер fetch клобберит rflags.** Каждый outer handler
   начинается с `movzx eax, byte [r11]; xor al, key; xor al, rolling;
   inc r11`. `xor` и `inc` — rflags-producers. Никакой
   "flag-preserving nop" не работает, если он выполняется ПОСЛЕ
   fetch'а (тот же самый trap, из-за которого реверт G4 dead opcodes).
   Вывод: **последний flag-producer перед возвратом во внешний tail
   dispatch должен быть именно гостевой ALU**. Схема 2 (scratch
   vflags slot) решает это явно.

3. **`ret` сохраняет rflags.** Единственный способ "протащить" rflags
   через вложенный call/ret без push/pop — чтобы терминальный ALU был
   последней flag-touching инструкцией перед `ret`. Никаких dispatch
   step'ов (`inc r12`, `add rax, r13`) между ALU и `ret`. Initial scope
   это гарантирует тем что терминал сразу делает `add [rsi], r14; ret`
   без возврата в диспетчер-loop. При расширении ISA — либо сохранить
   этот инвариант (схема 1/3), либо явно восстанавливать флаги из
   scratch slot'а (схема 2).

4. **Position independence — обязательна.** Диспетчер вызывается из
   outer хэндлера через `call rel32`, а сам живёт в том же .mxvm
   blob'е на неизвестном заранее offset'е. Весь inner runtime —
   только rip-relative `lea` и short `jmp rel8`. Handler table —
   signed int32 offsets от table base (не абсолютные адреса). Backend
   после emit'а handlers patch'ит список rel32 слотов в outer
   хэндлерах на абсолютный offset диспетчера — единственное внешнее
   исправление.

5. **Outer handler body для V2 варианта (подтверждённый шаблон).**

   ```
   <fetch операндных байтов>
   <compute rsi = dst slot addr>
   <compute rdi = src slot addr>
   lea r12, [rip + 2]     ; inner VPC на inline bytecode
   jmp  +N                ; перепрыгнуть через N байт bc
   <N байт inner bc>
   call rel32 inner_vm_entry  ; rel32 патчится backend'ом
   ; возврат через ret из терминального inner handler'а
   ; → выпадает в tail dispatch outer хэндлера
   ```

   Длина inner bc должна быть известна на момент emit'а outer
   handler'а (для `jmp +N`), т.е. outer-лифтер заранее знает во что
   лифтит.

6. **`r11` — outer VPC.** Из inner VM его трогать нельзя. Inner
   опкоды, которые читают/пишут memory, используют `rsi`/`rdi`, а не
   `r11`.

7. **Variant count и распределение.** В backend'е `variant_count_for(op)`
   определяет сколько разных handler body вариантов на opcode. G2
   добавляет ещё один вариант (V_last) к каждому nested-лифтимому
   хэндлеру. С тремя вариантами (V0 canonical, V1 MBA, V2 nested)
   encoder выбирает uniform'но per bytecode instruction — это уже
   подтверждённо работает.

#### План работы (sequential)

1. **Дизайн расширенной ISA.** Зафиксировать точный opcode set,
   операнды, register map (`r14` r_inner, `r15` tmp_inner). Прописать
   в `x64_inner_vm.hpp` как обновлённый header doc.
2. **Runtime emit для minimal multi-step** (load_src, load_dst,
   store_dst, ialu_rr, iret) с схемой 2 flag-propagation. Stress-тест
   на существующих `add_rr` — поведение должно совпасть с initial
   scope.
3. **Остальные r-r ALU** (`and_rr`, `or_rr`). Садятся на тот же
   runtime без изменений — только новые outer wrapper'ы.
4. **`mov_rr` и unary** (`not_r`, `neg_r`). Тривиально, по паттерну
   `iload_* / iunary / istore_dst / iret`.
5. **`*_ri32`** — требует inline imm в inner bc. Решить: либо
   отдельный `ialu_ri8` opcode с imm8 в bytecode, либо перенос imm32
   из outer fetch'а в r_inner через `iload_imm32`.
6. **Per-build randomization.** Opcode permutation, handler table
   shuffle, junk в диспетчере.
7. **vjcc-лифт.** Последний — требует `ibranch` и аккуратного vflags
   handling'а.
8. Обновить `x64_inner_vm.hpp` header doc + ROADMAP → G2-extended ✅.

#### Deliverables checklist

- [x] `include/mxprotector/protection/vm/x64/x64_inner_vm.hpp` — ISA
  enum, `kInnerVmRuntimeSize`, `emit_inner_vm_runtime`, ABI контракт.
- [x] `src/builder/protection/vm/x64/x64_inner_vm.cpp` — hand-assembled
  runtime с `static_assert` на каждый disp32 и байтовый размер.
- [x] `emit_handler_alu_rr_nested` в `x64_handlers.cpp`.
- [x] Backend wiring (`variant_count_for`, `emit_op_variant`,
  `inner_vm_call_patches`, patch loop).
- [x] Stress coverage для initial scope (90/90 strong).
- [x] Расширенная ISA (13 opcode'ов) в `x64_inner_vm.hpp/cpp` —
  152-byte runtime, multi-step threaded dispatcher.
- [x] Multi-step dispatch через **rcx-live flag carrier** (scheme 2
  variant). Scratch flag slot в памяти runtime оказался недоступен
  (.mxvm секция R+X, без W) — переиграно на host-register carrier.
- [x] V2 variant для `and_rr`/`or_rr` (вдобавок к add/sub/xor). 5 из 5
  r-r ALU хэндлеров лифтятся в nested VM. Stress 90/90 strong.
- [x] V2 variant для `mov_rr` (через flag-transparent `iload_src_accum`
  + `iret_noflag` pair).
- [x] V2 variant для `not_r` / `neg_r` (unary). `inot_r14` —
  flag-transparent, `ineg_r14` — flag-producing через rcx carrier.
- [x] Wrappers module `x64_inner_vm_wrappers.{hpp,cpp}`: все
  `emit_handler_*_nested` вынесены из `x64_handlers.cpp` + shared
  tail `emit_inner_vm_call`. Open/closed для следующих nested lifts.
- [x] Unit test `x64_inner_vm_runtime_test.cpp` — byte-for-byte blob
  pin + structural invariants + enum-index check + per-opcode
  handler body checks (11 тестов).
- [x] `emit_handler_{alu,mov}_ri32_nested` для всех 6 immediate-form
  хэндлеров (mov/add/sub/xor/and/or_ri32). Без новых inner opcode'ов:
  outer wrapper фетчит imm32 через `emit_fetch_dword` → `movsxd
  r14/r15, eax`, дальше inner runtime работает как обычно.
- [ ] Per-build inner-ISA randomization hook.
- [ ] vjcc-лифт через `ibranch` + scratch flag carrier.

### ⏳ G4. Bytecode semantic obfuscation *(высокий, средняя сложность)*

- **Handler id polymorphism** ✅ — shipped. 8 canonical ops
  (`mov_rr`, `add_rr`, `sub_rr`, `xor_rr`, `and_rr`, `or_rr`,
  `not_r`, `neg_r`) each have 2 alternative handler bodies. The
  encoder picks one at random per bytecode instruction via the
  existing `variant_handler_ids` path. Each handler table now holds
  2 bodies per targeted op; static opcode-table recovery has to
  distinguish shapes across the full variant set.

- 📋 **Dead opcodes** — deferred. The "reuse an existing ALU op
  with an identity imm" approach fails because every handler's
  operand fetch trashes host rflags and the tail dispatch saves
  them to vflags, so a flag-preserving body like `shl 0` still
  leaks garbage flags into vflags and a subsequent `vjcc` reads
  the wrong guest ZF/SF. Stochastic ~3% vjcc miss-branch under
  stress. Proper fix: custom dead-op handlers that stash vflags on
  entry and restore before tail dispatch — those are ~20 bytes
  each, don't reuse the generic emitter, and need new
  `variant_count_for` entries.

- 📋 **Opaque branches inside bytecode**: `VJCC` с всегда-ложным
  условием, уводящая на мертвую ветку handlers (которая сама
  корректно завершается).

- 📋 **Bytecode encryption с rolling key per-handler**: каждый
  handler XOR'ит следующий opcode byte ключом зависящим от своего
  handler_id. Static decode невозможен — только трассировкой.

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

### 📋 P2. Multi-layer unpacking *(высокий)*
VMProtect делает 3-5 слоёв: layer N раскрывает layer N+1, затем сам себя
стирает (`VirtualProtect` + memset). Reverser должен пройти все слои trace'ом.

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

### 📋 S5. Scan-resistant format: split across sections *(низкий, polish)*
String bytes разбросаны по нескольким non-`.rdata` секциям. Reassembly в
runtime decoder'е. `strings` и entropy scanners видят fragments.

### 📋 S6. Compiler-generated strings (RTTI, exceptions) *(низкий, сложный)*
MSVC embeds class names в RTTI, exception messages в `std::exception::what()`.
Частичное решение: `#pragma` вывод RTTI в отдельную секцию, packer
stream-cipher'ит, S2 pass проходит по XREF. Нерешаемые остатки — документировать
как known leak и рекомендовать `/GR-` for release builds.

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
