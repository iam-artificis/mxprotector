# MBA Expansion — Multi-Shape Rewriter Set

**Status:** shipped — phases 1–16 merged on master, all stress green.

**Roadmap completion:** all 5 deferred items from the original
roadmap (r-r MBA, REX.W full 64-bit operand, affine MBA over a
bitwise basis, multi-step deep chains, NOT/NEG MBA) shipped through
phases 8–13, plus all 3 deferred follow-on items (ALU multi-step
deep chains, NOT/NEG with deep chains, imm8 short-form coverage)
shipped through phases 14–16. Phase 16 also fixed a latent
multi-instruction-redirect hazard around jump targets that affected
phases 11+ but rarely triggered until imm8 sites broadened the MBA
match surface.

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

### Phase 13: NOT/NEG MBA

Two shapes per unary op (4 rewriters total) targeting `[REX] F7 /<2|3>`
with `mod = 3`. Each shape replaces the original unary opcode with
a binary-arithmetic chain so frequency matchers tracking unary
opcodes lose the signal.

| Shape (name)             | Identity              | Body                       |
| ------------------------ | --------------------- | -------------------------- |
| `not-rm-twocomplement`   | `~x = -x - 1`         | `neg dst ; sub dst, 1`     |
| `not-rm-xor-cancel`      | `~x = (x^K) ^ ~K`     | `xor dst, K ; xor dst, ~K` |
| `neg-rm-not-add1`        | `-x = ~x + 1`         | `not dst ; add dst, 1`     |
| `neg-rm-zero-sub`        | `-x = 0 - x`          | `mov s, dst ; xor dst, dst ; sub dst, s` |

Pairing inside each op:
* NOT — TWOCOMPLEMENT emits a NEG (changing the unary signal); 
  XOR-CANCEL emits zero unary opcodes at all (pure binary arithmetic).
* NEG — NOT-ADD1 emits a NOT (changing the unary signal); ZERO-SUB
  emits zero unary opcodes (`mov + xor + sub` chain).

The MBA adapter picks one of the two shapes uniformly per site, so
roughly half the NOT/NEG sites get each treatment. The `xor-cancel`
shape uses a per-site random `K` (forced outside imm8 range) for
visual polymorphism between sites.

2-byte (no REX) / 3-byte (with REX) sites — picked up via Phase 11's
multi-instruction redirect.

* New `mba_unary_decoder.hpp/cpp` decodes `[REX] F7 /<2|3>` with
  `mod = 3`. Memory operands and foreign /reg extensions rejected.
* 4 thin per-shape rewriter files + `unary_aggregator.cpp`.
* 5 new decoder tests + 4 new semantic tests over a 5-element
  sample set (including the `x = 0` and `x = -1` boundary values).

### Phase 12: Register-register ALU MBA

Five new affine shapes targeting the group-1 r-r ALU encodings
`01/03/09/0B/21/23/29/2B/31/33 /r` with `mod = 3`. Each shape uses
the same coefficient algebra as the imm32 affine shapes but reads
from a register source instead of an immediate.

| Shape (name)  | Identity                                              |
| ------------- | ----------------------------------------------------- |
| `add-rr-affine` | `(1+t)*(x|y) + (1-t)*(x&y) - t*(x^y) = x + y`     |
| `sub-rr-affine` | ADD body, then `dst -= src; dst -= src`           |
| `xor-rr-affine` | `(1-t)*(x|y) + (t-1)*(x&y) + t*(x^y) = x ^ y`     |
| `or-rr-affine`  | `-t*(x|y) + (1+t)*(x&y) + (1+t)*(x^y) = x | y`    |
| `and-rr-affine` | `(1+t)*(x|y) - t*(x&y) - (1+t)*(x^y) = x & y`     |

Same per-site `t ∈ [2, 15]` parameterisation — 14 SMT-distinct
shapes per op, identical defeat strength to the imm32 affine path.

The targeted instructions are 2 bytes (no REX) or 3 bytes (with
REX) — below the 5-byte JMP rel32 redirect threshold. Phase 11's
multi-instruction redirect engine drags the next 1..3 instructions
into the slot to widen it to ≥ 5 bytes.

* New `mba_alu_rr_decoder.hpp/cpp` accepts both encoding directions
  (rm-r `01 /r` and r-rm `03 /r`) and normalises to a single
  `(dst, src)` view. Same-register sites (`xor r, r` zero idiom)
  and memory-operand variants are rejected at decode.
* New `pick_three_scratches_for(dst, src)` overload that walks a
  6-deep candidate list (`r10..r15`) so neither operand register
  is aliased by a scratch. The original imm32 picker (1-arg) is
  unchanged.
* New `emit_affine_alu_rr_body` shares all the coefficient logic
  with the imm32 path; only the basis-prep and SUB-correction
  switch from imm operand to register operand.
* 5 thin per-shape rewriter files + 1 aggregator file
  (`rr_affine_aggregator.cpp`) wire factories into the registry.
* `MbaSubstitutionRule` adapter is unchanged — it dispatches to the
  registry generically, so r-r shapes are picked up automatically.

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
  - phase 8: REX.W sign-extension for `IMUL r64, r/m64, imm32`.
  - phase 9: `0x6B /r ib` IMUL r,r,imm8 for affine small-coef path.
  - phase 10: `0xD1` extended to ROL/ROR/SHL/SHR by 1 (was SHL only).

* Full ctest at every phase: 894 → 939 tests, all passing.

* Stress per phase: 15 runs at strong + 15 at maximum.
  Final sweep (phase 8): 10 runs each at minimal/standard/strong/
  maximum — **40/40 PASS**.

## Numbers (test_vm_showcase.exe at strong)

| Metric                          | Phase 9 | Phase 10 | Phase 11 | Phase 12 | Phase 13 | Phase 14 | Phase 15 | Phase 16 |
| ------------------------------- | ------- | -------- | -------- | -------- | -------- | -------- | -------- | -------- |
| MBA rewriters in registry       | 26      | 29       | 29       | 34       | 38       | 43       | 45       | 45       |
| Per-ALU-imm shape options (32b) | 4       | 4        | 4        | 4        | 4        | 5        | 5        | 5        |
| Per-ALU-imm shape options (64b) | 4       | 4        | 4        | 4        | 4        | 4        | 4        | 4        |
| Per-ALU-rr shape options        | 0       | 0        | 0        | 1        | 1        | 1        | 1        | 1        |
| Per-MOV-imm32 shape options     | 3       | 3 + 3    | 3 + 3    | 3 + 3    | 3 + 3    | 3 + 3    | 3 + 3    | 3 + 3    |
| Per-MOV-imm64 shape options     | 3       | 3        | 3        | 3        | 3        | 3        | 3        | 3        |
| Per-NOT shape options (32b)     | 0       | 0        | 0        | 0        | 2        | 2        | 3        | 3        |
| Per-NEG shape options (32b)     | 0       | 0        | 0        | 0        | 2        | 2        | 3        | 3        |
| imm8 short-form coverage        | n/a     | n/a      | n/a      | n/a      | n/a      | n/a      | n/a      | yes      |
| Affine `t` choices per site     | 14      | 14       | 14       | 14       | 14       | 14       | 14       | 14       |
| Multi-instruction redirect      | n/a     | n/a      | yes      | yes      | yes      | yes      | yes      | yes      |
| Jump-target gate (engine)       | n/a     | n/a      | n/a      | n/a      | n/a      | n/a      | n/a      | yes      |
| MBA tests                       | 54      | 57       | 57       | 68       | 77       | 86       | 89       | 96       |
| Total ctest                     | 925     | 928      | 928      | 939      | 948      | 954      | 957      | 964      |
| Stress (strong, 15 runs)        | 15/15   | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    |
| Stress (maximum, 15 runs)       | 15/15   | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    | 15/15    |

Phase 8 does not change redirect-site count on the showcase binary
because that input is compiled with `mov r32, imm32` for all 32-bit
constants — the 64-bit `mov r64, imm64` form is a compiler choice
driven by 64-bit-typed constants larger than `INT32_MAX` (or marked
`uint64_t`). On binaries that genuinely use `mov r64, imm64` (signed
64-bit table indices, Windows handle constants, AES round-key
loaders), the new shapes contribute additional polymorphism. The
infrastructure cost is paid up front: future MBA work that targets
64-bit constants now has a working decoder + emitter contract.

### Phase 14: ALU multi-step deep chains

Five new shapes (`<op>-imm-deep-affine` for ADD/SUB/XOR/OR/AND).
Outer is the `<op>-imm-affine` body; inner materialises K through a
random MOV-imm MBA shape (modular-inverse / xor-blind /
rotate-blind) into a scratch register, then basis prep does
`op s, dst` (commutative). Stacks two MBA proofs in series.

Constraint: 32-bit operand only (`is_64bit==false`). The 32-bit
MOV-imm step functions zero-extend their destination — REX.W
support would need an extra `movsxd` after K materialisation;
documented as a roadmap extension.

Per-site variability per ALU op: 3 inner shapes × 14 affine `t`
choices = 42 SMT-distinct identities, in addition to the existing
17 from the fixed + affine shapes.

### Phase 15: NOT/NEG with deep chains

Two new shapes:

* `not-rm-deep-xor` — `~x = (x^K) ^ ~K` with K and ~K each
  materialised via random MOV-imm MBA shape (modular-inverse /
  xor-blind / rotate-blind) into a scratch register. The xor-cancel
  uses the register form `xor dst, scratch` so the body emits zero
  unary opcodes AND zero direct imm32 xor opcodes.
* `neg-rm-deep-add` — `-x = ~x + K - (K-1)` with K and K-1 each
  materialised via random MOV-imm MBA shape. Outer body has only
  the initial NOT plus register-form ALU ops on the scratch.

Same 32-bit operand constraint as Phase 14. Per-site variability:
3 × 3 inner combinations × 2^31 K values = the deepest defeat
strength of any shipped unary shape.

### Phase 16: ALU imm8 short-form support

Decoder change: `decode_alu_imm32` now also accepts the imm8 form
`[REX] 83 /op ib` (3 bytes no-REX, 4 bytes with REX). Sign-extends
imm8 → int32 in `view.imm` so every existing imm32 rewriter applies
unchanged — no new shape files needed.

Decoder safety gate: `decode_alu_imm32`, `decode_alu_rr`, and
`decode_unary` now reject rsp dst (and rsp src for r-r). The MBA
bodies wrap their work in `push scratch ... pop scratch` which
corrupts a body that reads `view.dst == rsp`. Compilers emit
`[REX.W] 83 /op ib` on rsp very aggressively (`sub rsp, 0x28` etc.),
so the rsp gate is mandatory for imm8 support.

Engine change (latent bug surfaced by Phase 16):
`MutationEngine::mutate_region` now collects every branch target
in the region and refuses to consume a jump-landing site during
multi-instruction redirect widening. Without this, the planted
`JMP rel32 + NOP pad` swallows a basic-block head, breaking any
`jcc` that lands there. The hazard existed since Phase 11 but was
rare in practice; imm8 ALU sites are common enough at the heads of
basic blocks that the bug fires every build.

Coverage uplift: imm8 sites are ~3-5× more common than imm32 sites
in optimised compiler output. Every shipped MBA shape (fixed +
affine + deep-affine + r-r affine + unary fixed + unary deep) now
covers imm8 sites in addition to imm32.

## Roadmap (not in this expansion)

The roadmap is now complete — all 5 originally-deferred items plus
all 3 follow-on items have shipped. Any future MBA work would be a
fresh expansion, not a continuation of this plan. Possible
directions, not committed:

1. **64-bit deep-affine + deep-unary**: the deep-chain shapes from
   phases 14–15 are gated to 32-bit destinations because their MOV-
   imm step functions zero-extend the high half of the scratch.
   64-bit support needs an explicit `movsxd scratch, scratch_lo32`
   after each K materialisation.

2. **Multi-step depth ≥ 3**: the deep-chain shapes today stack two
   MBA layers. Adding a third layer would require extending
   `MovImmEmitter` to accept its own `inner` override (currently
   only the *outer* layer is parameterisable). Diminishing returns
   per layer; better defeat-strength path is broader basis families.

3. **Tigress-style 2-parameter affine**: today's affine combinator
   has one parameter `t`. A 2-parameter family `(t, u)` over a
   4-element basis would multiply the per-site shape count without
   touching the body skeleton.
