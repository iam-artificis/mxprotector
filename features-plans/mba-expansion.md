# MBA Expansion — Multi-Shape Rewriter Set

**Status:** shipped — phases 1–10 merged on master, all stress green.

## What this is

Mixed-Boolean-Arithmetic (MBA) rewriting in MxProtector replaces
trivially-foldable ALU and MOV-imm instructions with algebraically-
equivalent byte sequences that defeat SMT-solver constant folding.
The original effort shipped one rewriter per ALU family + one
modular-inverse `mov`-imm rewriter (6 rewriters total).

This expansion adds **multi-shape polymorphism**: every supported
op now has 3 structurally-different identities, picked uniformly
at random per call site. Two `add r, K` instructions in the same
binary get visibly different MBA bodies.

## Scope shipped

### Phase 1–5: Multi-shape ALU-imm rewriters

For each of the 5 ALU operations (ADD/SUB/XOR/OR/AND), three SMT-
distinct identities now match the same `81 /op id` and short-form
sites:

| Op  | Shape 1 (existing)         | Shape 2 (new)              | Shape 3 (new)              |
| --- | -------------------------- | -------------------------- | -------------------------- |
| ADD | `(x ^ K) + 2*(x & K)`      | `(x \| K) + (x & K)`       | `2*(x \| K) - (x ^ K)`     |
| SUB | `(x ^ K) - 2*(~x & K)`     | `x + (~K + 1)`             | `(x^K) + 2*(x&K) - 2K`     |
| XOR | `(x \| K) - (x & K)`       | `(x \| K) ^ (x & K)`       | `(x + K) - 2*(x & K)`      |
| OR  | `(x ^ K) + (x & K)`        | `x + K - (x & K)`          | `(x ^ K) \| (x & K)`       |
| AND | `(x \| K) - (x ^ K)`       | `(x + K) - (x \| K)`       | `~(~x \| ~K)`              |

Each shape is a separate `IMbaRewriter` class in its own file under
`src/builder/protection/mutation/mba/rewriters/`. The per-family
aggregator (`register_<op>_imm_rewriters`) registers all three.

### Phase 6: Short-form 5-byte ALU encodings

The imm32 ALU decoder now also accepts `[REX.W] {05|0D|25|2D|35} id`
— the EAX/RAX-only short forms. These are exactly 5 bytes (no REX)
or 6 (with REX.W), fitting the JMP rel32 redirect threshold.

Coverage uplift on `test_vm_showcase.exe` at strong: redirect count
180 → 195 (**+8.3%**). On binaries with more RAX-bound arithmetic
(syscall stubs, ABI shims) the uplift will be larger.

### Phase 10: Multi-step deep MBA chains

Three new MOV-imm rewriter shapes that compose two MBA layers at
the abstract-operation level — *no byte-level surgery*. Each shape
runs an outer single-layer body but materialises the leading
immediate via a different MBA shape's full body, picked uniformly
at random per call site:

| Shape (name)             | Outer            | Inner pool                       |
| ------------------------ | ---------------- | -------------------------------- |
| `mov-imm-deep-modular`   | modular-inverse  | {xor-blind, rotate-blind}        |
| `mov-imm-deep-xor`       | xor-blind        | {modular-inverse, rotate-blind}  |
| `mov-imm-deep-rotate`    | rotate-blind     | {modular-inverse, xor-blind}     |

The composition is wired through a new `MovImmEmitter` typedef +
shared step functions in `mov_imm_emit.hpp`:

```cpp
emit_modular_inverse_step(em, dst, K, rng,
    inner = direct_mov_imm32);  // single-layer
emit_modular_inverse_step(em, dst, K, rng,
    inner = &emit_xor_blind);    // 2-layer deep chain
```

Each per-shape rewriter is a thin adapter — decode, pick inner,
call the step, build. The existing single-layer rewriters were
refactored to call the shared step functions with the default
`direct_mov_imm32` inner, so 100% of the per-shape semantic
coverage survives unchanged.

Body length: 3 instructions (≈ 11–17 bytes). SMT defeat: stacks
two proofs in series — the outer finalizer proof must hand off to
the inner-shape proof, doubling the per-site solver-time cost
relative to the single-layer shapes.

Why no ALU multi-step in this phase: the imm32 ALU bodies have
3-scratch-register affine-MBA shapes that already span the
0..16 range of distinct identities per `t`. Composing those
across layers would require a more invasive refactor of the
affine-emit path. Roadmap'd for a future expansion.

### Phase 9: Affine MBA basis combinator (Tigress-style)

A fifth shape per ALU family — `<op>-imm-affine` — emits a *random
integer linear combination* of three bitwise-basis functions:

    f(x, K) = c_or*(x|K) + c_and*(x&K) + c_xor*(x^K) (+ post)

The coefficient triple is parameterised by a per-site random
`t ∈ [2, 15]`, exploiting the zero-identity
`(x|K) - (x&K) - (x^K) ≡ 0 (mod 2^n)` to add any integer multiple
of zero to a base shape without changing the result. Per-op maps:

| Op  | (c_or, c_and, c_xor) | Post-correction |
| --- | -------------------- | --------------- |
| ADD | `(1+t, 1-t, -t)`     | —               |
| SUB | `(1+t, 1-t, -t)`     | `dst -= 2K` (split as 2× `sub dst, K`) |
| XOR | `(1-t, t-1, t)`      | —               |
| OR  | `(-t, 1+t, 1+t)`     | —               |
| AND | `(1+t, -t, -(1+t))`  | —               |

That gives **14 SMT-distinct identities per op** in the affine
shape alone, on top of the 3 fixed shapes — so a single ALU site
now has 17 candidate identities (4 register slots × diversity in
coefficients) instead of 3. Frequency-pattern matchers that key on
the canonical Knuth/disjoint coefficient triples cannot keep up
with a per-site randomly chosen `t`.

The body uses three scratch registers via a new
`wrap_with_push_pop_3` helper: one slot per basis term so the
multiplications fan out cleanly. `emit_imul_const` folds `c == -1`
into `neg`, `c == 1` into a no-op, and `c == 0` into `xor reg, reg`,
keeping the body free of redundant operations. The shared emitter
`emit_affine_alu_body` parameterises by `(view, coefficients)` so
each per-family rewriter file is a thin wrapper (≤ 80 LOC).

### Phase 8: REX.W full 64-bit MOV-imm

The `mov r64, imm64` 10-byte form (`[REX.W (.B)] B8+rd iq`) is now
matched by a parallel set of three rewriter shapes — one-to-one with
the 32-bit MOV-imm set. A new decoder
(`decode_mov_r64_imm64`) handles the 10-byte encoding; bodies use a
new `X86CodeEmitter::mov_abs64` helper that locks in the 10-byte
shape regardless of how many high bits of the encoded value are set
(the size-optimal default downgrades to the 7-byte sign-extended
shape, which silently inverts the high half of the value when bit 31
is set).

| Shape (name)                  | Identity                              | SMT cost     |
| ----------------------------- | ------------------------------------- | ------------ |
| `mov-imm64-modular-inverse`   | `mov K' ; imul P32`                   | High         |
|                               | `K' = K · inv(sext64(P32))`           |              |
| `mov-imm64-xor-blind`         | `mov A ; xor B32`                     | Trivial fold |
|                               | `A = K ^ sext64(B32)`                 |              |
| `mov-imm64-rotate-blind`      | `mov ror64(K, n) ; rol n`             | Trivial fold |

Why a separate shape set instead of generalising the imm32 path:
the 64-bit body shapes have to navigate around imm32 sign-extension
in `imul r64,r/m64,imm32` and `xor r/m64,imm32` — pulling all of
that into the 32-bit rewriters would double their per-shape branch
density.  Single-responsibility per rewriter file kept the change
mechanical: 3 new files, 1 decoder addition, 1 emitter helper, 0
edits to existing 32-bit rewriters.

### Phase 7: Multi-shape MOV imm32 rewriters

| Shape (name)             | Identity                          | SMT cost          |
| ------------------------ | --------------------------------- | ----------------- |
| `mov-imm-modular-inverse`| `mov K' ; imul P` (K' = K·inv(P)) | High (mod inv)    |
| `mov-imm-xor-blind`      | `mov A ; xor A^K`                 | Trivial fold      |
| `mov-imm-rotate-blind`   | `mov ror(K,n) ; rol n`            | Trivial fold      |

Strongest defeat (`mov-imm-modular-inverse`) still picked 1/3 of
the time. The cheaper shapes provide visual polymorphism and a
wider per-site instruction vocabulary (rotate-blind emits `rol`,
which neither of the others uses).

## Architecture

* `mba_rewriter_factories.hpp` — declares one `make_<shape>()`
  factory per shape. Adding a shape: new file under
  `rewriters/`, one factory decl, one call in the per-family
  aggregator.
* Per-family aggregator (`register_<op>_imm_rewriters`) lives in
  the file housing the original "shape 1" rewriter for each op,
  by convention. It calls all factories for that op family.
* `mov_imm_decoder.hpp` — shared decoder for `B8+rd id`, consumed
  by all three MOV-imm rewriters.
* `mba_alu_imm_decoder.hpp` — shared decoder for `[REX] 81 /op id`
  AND `[REX.W] {05|0D|...} id` short forms.

OCP: extending the registry is one new file + one factory + one
aggregator call. No edits to existing rewriter files.

## Test coverage

* 38 MBA tests in `tests/unit/mba_rewriter_test.cpp`:
  - 8 decoder tests (`81` form + short forms + REX.B + foreign-op
    rejection).
  - 13 per-shape semantic-equivalence tests (5×3 ALU + 3 MOV-imm),
    each running 5 sample x values × 5 sample K values through a
    local x86-64 simulator.
  - 6 registry tests (size, find, find_matching for ADD / SUB /
    short-form ADD / short-form SUB).
  - 5 adapter (`MbaSubstitutionRule`) tests: registration gating,
    matches outside MBA-covered ops, flag-affecting flag, expansion
    size.

* `MbaSimulator` test harness extended through phases:
  - phase 2: `REX.W + B8+rd qword` (10-byte mov r64, imm64) for
    SUB-imm-neg-add's mov scratch, K with negative K.
  - phase 2: `REX.W + C7 /0 id` sign-extension to 64 bits.
  - phase 7: `C1 /op ib` for ROL/ROR/SHL/SHR r/m, imm8.

* Full ctest at every phase: 894 → 909 tests, all passing.

* Stress per phase: 15 runs at strong + 15 at maximum.
  Final sweep (phase 8): 10 runs each at minimal/standard/strong/
  maximum — **40/40 PASS**.

## Numbers (test_vm_showcase.exe at strong)

| Metric                       | Phase 7 | Phase 8 | Phase 9 | Phase 10 |
| ---------------------------- | ------- | ------- | ------- | -------- |
| MBA rewriters in registry    | 18      | 21      | 26      | 29       |
| Per-ALU shape options        | 3       | 3       | 4       | 4        |
| Per-MOV-imm32 shape options  | 3       | 3       | 3       | 3 + 3    |
| Per-MOV-imm64 shape options  | n/a     | 3       | 3       | 3        |
| Affine `t` choices per site  | n/a     | n/a     | 14      | 14       |
| MBA tests                    | 38      | 49      | 54      | 57       |
| Total ctest                  | 909     | 920     | 925     | 928      |
| Stress (strong, 15 runs)     | 15/15   | 15/15   | 15/15   | 15/15    |
| Stress (maximum, 15 runs)    | 15/15   | 15/15   | 15/15   | 15/15    |

Phase 8 does not change redirect-site count on the showcase binary
because that input is compiled with `mov r32, imm32` for all 32-bit
constants — the 64-bit `mov r64, imm64` form is a compiler choice
driven by 64-bit-typed constants larger than `INT32_MAX` (or marked
`uint64_t`). On binaries that genuinely use `mov r64, imm64` (signed
64-bit table indices, Windows handle constants, AES round-key
loaders), the new shapes contribute additional polymorphism. The
infrastructure cost is paid up front: future MBA work that targets
64-bit constants now has a working decoder + emitter contract.

## Roadmap (not in this expansion)

The following are higher-effort or higher-risk and were not
attempted in this pass:

1. **Register-register MBA**: covers `01/03/09/0B/21/23/29/2B/31/33 /r`
   forms. Bodies need multi-variable identities (e.g. `x + y =
   (x^y) + 2*(x&y)`). Requires multi-instruction redirect because
   r-r encodings are 2–3 bytes — below the JMP rel32 threshold.

2. **NOT/NEG MBA**: `not r/m` is 3 bytes, `neg r/m` is 3 bytes —
   below the JMP rel32 threshold. Same multi-instruction-redirect
   prerequisite as r-r forms.

3. **ALU multi-step deep chains**: extend the Phase-10 deep-chain
   pattern to imm32 ALU rewriters by routing each basis-prep
   `or/and/xor reg, K` in the affine body through a recursive MBA
   layer. Requires a small refactor of `emit_affine_alu_body` to
   accept per-term `MovImmEmitter`-style overrides for the K-
   materialization. Mostly mechanical once the contract is in
   place; saved for a future MBA expansion.
