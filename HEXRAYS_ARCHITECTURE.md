# How Hex-Rays actually works — read out of the official SDK

Source: `C:\Users\hhhuh\Downloads\ida-sdk-main\ida-sdk-main\src\include\hexrays.hpp`
(14,138 lines), the header Hex-Rays ships for plugin authors. It documents the
decompiler's real internal architecture, not a reimplementation of it.

This matters because the decompiler is the hardest part of what we are building,
and we no longer have to invent its design.

## The pipeline: nine maturity levels

`mba_maturity_t` is the whole decompiler in one enum:

```
MMAT_ZERO           microcode does not exist
MMAT_GENERATED      generated microcode          <- lift x86 to IR
MMAT_PREOPTIMIZED   preoptimized pass complete
MMAT_LOCOPT         per-block optimization done; CFG is ready
MMAT_CALLS          call arguments detected
MMAT_GLBOPT1        first global optimization pass
MMAT_GLBOPT2        most global optimization done
MMAT_GLBOPT3        all global optimization; microcode is now fixed
MMAT_LVARS          local variables allocated    <- then structure to C
```

The design lesson: decompilation is **not one transformation**. It is a sequence
of passes over a stable IR, each cheap and individually testable. A v1 can stop
early — useful pseudocode is possible at `LOCOPT` + basic structuring, long
before the global optimizer exists.

## The IR: 73 opcodes, and that is all

`mcode_t` is far smaller than x86. The entire instruction set lifts down to:

| group | opcodes |
|---|---|
| data movement | `nop stx ldx ldc mov` |
| arithmetic | `neg add sub mul udiv sdiv umod smod` |
| bitwise | `lnot bnot or and xor shl shr sar` |
| width | `xds xdu low high` |
| flags | `cfadd ofadd cfshl cfshr` |
| conditions | `sets seto setp setnz setz setae setb seta setbe setg setge setl setle` |
| control flow | `jcnd jnz jz jae jb ja jbe jg jge jl jle jtbl ijmp goto` |
| calls | `call icall ret push pop` |
| float | `f2i f2u i2f u2f f2f fneg fadd fsub fmul fdiv` |
| other | `und ext` |

**73 opcodes covers x86-64.** That is the single most encouraging fact for our
build: the lifter is a large but mechanical mapping, not a research problem.

Note what is absent — there is no `m_cmp` or `m_test`. Comparisons become
explicit flag computations (`setz`, `setb`, …) or fused conditional jumps
(`m_jz l, r, d`). Flags are values, not hidden state. That is what makes the
optimizer able to reason about them.

## Operands: 16 kinds

```
mop_z    none                     mop_b    micro basic block
mop_r    register                 mop_f    list of arguments
mop_n    immediate constant       mop_l    local variable
mop_str  immediate string         mop_a    address of an operand
mop_d    result of another insn   mop_h    helper function
mop_S    local stack variable     mop_c    switch cases
mop_v    global variable          mop_fn   floating constant
                                  mop_p    operand pair
                                  mop_sc   scattered operand
```

`mop_d` — "result of another instruction" — is the key one. It is what lets the
IR nest: an instruction's operand can be another whole instruction, so
expression trees fall out of the IR directly rather than needing a separate
expression builder.

`mop_r` and `mop_S` are documented as existing "until MMAT_LVARS", when they
become `mop_l`. Register and stack allocation is undone late, which is exactly
why the output reads like source rather than assembly.

## What this changes about our plan

1. **Copy the IR.** 73 opcodes, 16 operand kinds. Designing our own would be
   strictly worse and take weeks.
2. **Copy the staged pipeline.** Ship `GENERATED -> LOCOPT -> structure` first
   and add optimization passes later. Each stage is independently testable,
   which is the only realistic way to build this incrementally.
3. **Flags as values.** Lift `cmp`/`test` into explicit flag computations
   immediately. Anything else makes conditional-jump handling intractable.
4. **Nested operands give expressions free.** No separate expression-building
   stage.

## Honest scope

Hex-Rays has ~30 years of work in the optimizer and type inference. We will not
match it on hard cases — heavily optimized code, unusual calling conventions,
deep type recovery.

What we can match, and what the job actually needs: **readable pseudocode for
typical functions**, in a live process, fast, scriptable, with no timeouts.

## Other SDK headers worth mining

| header | lines | what it gives |
|---|---|---|
| `hexrays.hpp` | 14,138 | microcode IR, CTree, the pipeline above |
| `typeinf.hpp` | 6,851 | type representation and inference model |
| `bytes.hpp` | 2,861 | how IDA tracks what each byte IS (code/data/head) |
| `funcs.hpp` | 1,987 | function/chunk model, tails, frames |
| `segment.hpp` | 1,833 | segment model |
| `ua.hpp` | 1,665 | instruction representation, operand decoding |
| `gdl.hpp` | 586 | graph/CFG interfaces |
| `xref.hpp` | 449 | the xref model — worth copying wholesale, it is small |
