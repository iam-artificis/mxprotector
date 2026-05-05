# MBA Expansion — Multi-Shape Rewriter Set

**Status:** shipped — phases 1–7 merged on master, all stress green.

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

| Metric                       | Baseline | After phase 7 |
| ---------------------------- | -------- | ------------- |
| MBA rewriters in registry    | 6        | 18            |
| MBA-redirected sites         | 180      | 195 (+8.3%)   |
| Total substitutions          | 5105     | 5120          |
| Per-family shape options     | 1        | 3             |
| MBA tests                    | 21       | 38            |
| Total ctest                  | 894      | 909           |
| Stress (strong, 15 runs)     | 15/15    | 15/15         |
| Stress (maximum, 15 runs)    | 15/15    | 15/15         |

## Roadmap (not in this expansion)

The following are higher-effort or higher-risk and were not
attempted in this pass:

1. **Register-register MBA**: covers `01/03/09/0B/21/23/29/2B/31/33 /r`
   forms. Bodies need multi-variable identities (e.g. `x + y =
   (x^y) + 2*(x&y)`). Requires multi-instruction redirect because
   r-r encodings are 2–3 bytes — below the JMP rel32 threshold.

2. **REX.W full 64-bit operand**: today `is_64bit` propagates
   correctly through the emitter, but the body still treats `K` as
   sign-extended 32-bit. Genuine 64-bit immediates need `mov r64,
   imm64` (10-byte) bodies and a new emit path for 64-bit ALU with
   non-imm32 constants.

3. **Affine MBA over a 16-element bitwise basis**: the Tigress-
   style technique. Requires a builder that emits a random linear
   combination of basis expressions, with per-site coefficients.
   Complex but very strong against SMT.

4. **Multi-step deep chains**: re-apply the rewriter pipeline to
   the output of one MBA body, producing nested expansions. Cheap
   to wire (one extra pass invocation), but increases binary size
   significantly.

5. **NOT/NEG MBA**: `not r/m` is 3 bytes, `neg r/m` is 3 bytes —
   below the JMP rel32 threshold. Same multi-instruction-redirect
   prerequisite as r-r forms.
