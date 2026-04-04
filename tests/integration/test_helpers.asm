; =============================================================================
; test_helpers.asm
; [TESTS] ASM-хелперы для интеграционного тестирования indirect syscall gate.
;
; Предоставляет низкоуровневую верификацию, невозможную из C++:
;   - nonvolatile_check_syscall: проверка сохранности non-volatile GPR
;     (RBX, RBP, RDI, RSI, R12-R15) при реальном indirect syscall вызове.
;   - alignment_check_13args: проверка 16-byte выравнивания стека
;     при вызове функции с 13 параметрами (максимум indirect_syscall).
;
; Собирается только для integration tests. Требует MSVC x64 + MASM (ml64).
; =============================================================================

EXTERN indirect_syscall:PROC

.code

; =============================================================================
; nonvolatile_check_syscall(ssn, syscall_addr, handle)
;
; Выполняет NtClose(handle) через indirect_syscall, одновременно
; проверяя, что все non-volatile GPR сохранены после возврата.
;
; Алгоритм:
;   1. Сохраняем оригинальные non-volatile GPR на стеке
;   2. Загружаем уникальные sentinel-значения во все non-volatile GPR
;   3. Вызываем indirect_syscall (NtClose) через стандартный CALL
;   4. Сравниваем каждый регистр с sentinel-значением
;   5. Восстанавливаем оригинальные GPR, возвращаем bitmask
;
; Вызов (x64 ABI):
;   ECX  = SSN для NtClose
;   RDX  = адрес `syscall; ret` гаджета
;   R8   = handle для закрытия
;
; Возвращает:
;   0 = все non-volatile GPR сохранены (ожидаемый результат).
;   Ненулевой bitmask повреждённых регистров:
;     bit 0 (01h) = RBX    bit 4 (10h) = R13
;     bit 1 (02h) = RDI    bit 5 (20h) = R14
;     bit 2 (04h) = RSI    bit 6 (40h) = R15
;     bit 3 (08h) = R12    bit 7 (80h) = RBP
; =============================================================================
nonvolatile_check_syscall PROC

    ; --- Prologue: сохраняем non-volatile GPR ---
    push    rbp
    push    rbx
    push    rdi
    push    rsi
    push    r12
    push    r13
    push    r14
    push    r15

    ; Математика выравнивания:
    ;   На входе RSP ≡ 8 (mod 16) — CALL вызывающего кода положил return address.
    ;   8 pushes = 64 байта. RSP ≡ (8 + 64) mod 16 = 8 (mod 16).
    ;   sub 0x88 = 136: RSP ≡ (8 + 136) mod 16 = 0 (mod 16).
    ;   Перед нашим CALL indirect_syscall: RSP ≡ 0 → корректно.
    sub     rsp, 88h

    ; Layout (от RSP):
    ;   [00h..1Fh]  shadow space (для indirect_syscall)
    ;   [20h..67h]  stack args: 9 qwords (arg3..arg11, все нули)
    ;   [68h..6Bh]  saved ECX (ssn, 32-bit)
    ;   [70h..77h]  saved RDX (syscall_addr)
    ;   [78h..7Fh]  saved R8  (handle)
    ;   [80h..87h]  alignment padding

    ; Сохраняем входные аргументы (volatile regs)
    mov     dword ptr [rsp + 68h], ecx
    mov     [rsp + 70h], rdx
    mov     [rsp + 78h], r8

    ; --- Загружаем sentinel-значения в non-volatile GPR ---
    mov     rbx, 1111111111111111h
    mov     rdi, 2222222222222222h
    mov     rsi, 3333333333333333h
    mov     r12, 4444444444444444h
    mov     r13, 5555555555555555h
    mov     r14, 6666666666666666h
    mov     r15, 7777777777777777h
    mov     rbp, 8888888888888888h

    ; --- Подготовка CALL к indirect_syscall(ssn, addr, handle, 0, ..., 0) ---
    mov     ecx, dword ptr [rsp + 68h]
    mov     rdx, [rsp + 70h]
    mov     r8,  [rsp + 78h]
    xor     r9d, r9d

    xor     rax, rax
    mov     [rsp + 20h], rax
    mov     [rsp + 28h], rax
    mov     [rsp + 30h], rax
    mov     [rsp + 38h], rax
    mov     [rsp + 40h], rax
    mov     [rsp + 48h], rax
    mov     [rsp + 50h], rax
    mov     [rsp + 58h], rax
    mov     [rsp + 60h], rax

    call    indirect_syscall

    ; --- Проверяем sentinel-значения ---
    xor     eax, eax

    mov     rcx, 1111111111111111h
    cmp     rbx, rcx
    je      chk1
    or      eax, 01h
chk1:
    mov     rcx, 2222222222222222h
    cmp     rdi, rcx
    je      chk2
    or      eax, 02h
chk2:
    mov     rcx, 3333333333333333h
    cmp     rsi, rcx
    je      chk3
    or      eax, 04h
chk3:
    mov     rcx, 4444444444444444h
    cmp     r12, rcx
    je      chk4
    or      eax, 08h
chk4:
    mov     rcx, 5555555555555555h
    cmp     r13, rcx
    je      chk5
    or      eax, 10h
chk5:
    mov     rcx, 6666666666666666h
    cmp     r14, rcx
    je      chk6
    or      eax, 20h
chk6:
    mov     rcx, 7777777777777777h
    cmp     r15, rcx
    je      chk7
    or      eax, 40h
chk7:
    mov     rcx, 8888888888888888h
    cmp     rbp, rcx
    je      chk8
    or      eax, 80h
chk8:

    ; --- Epilogue ---
    add     rsp, 88h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rsi
    pop     rdi
    pop     rbx
    pop     rbp
    ret

nonvolatile_check_syscall ENDP

; =============================================================================
; alignment_check_13args(p1, p2, ..., p13)
;
; Принимает 13 параметров — тот же layout, что и indirect_syscall.
; Проверяет, что RSP на входе корректно выровнен по Windows x64 ABI:
; после CALL'а RSP ≡ 8 (mod 16).
;
; Зачем: при 13 параметрах компилятор выделяет 0x48 байт стековых аргументов
; (9 qwords) + 0x20 shadow = 0x68 байт. Если компилятор допустит ошибку
; выравнивания, movaps в ядре упадёт с #GP.
;
; Возвращает:
;   0 если выравнивание корректно (RSP ≡ 8 mod 16).
;   Ненулевое значение при нарушении.
; =============================================================================
alignment_check_13args PROC
    mov     rax, rsp
    and     rax, 0Fh
    sub     rax, 8
    ret
alignment_check_13args ENDP

END
