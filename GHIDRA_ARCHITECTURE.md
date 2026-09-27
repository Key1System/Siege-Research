# Ghidra's decompiler — the parts worth copying

Source: `C:\Users\hhhuh\Downloads\ghidra-Ghidra_12.1.3_build\...\Features\Decompiler\src\decompile\cpp`
— **150,229 lines of production C++**, Apache 2.0, complete.

This is categorically more useful than the IDA SDK. The SDK describes an
architecture; this *is* an implementation, with the algorithms that make
decompiler output readable rather than merely correct.

## P-code: 74 opcodes

`opcodes.hh`. Same order of magnitude as Hex-Rays' 73 micro-ops, which is
strong independent confirmation that ~75 operations is genuinely what x86-64
lifts down to.

| group | ops |
|---|---|
| move/memory | `COPY LOAD STORE` |
| control flow | `BRANCH CBRANCH BRANCHIND CALL CALLIND CALLOTHER RETURN` |
| int compare | `INT_EQUAL INT_NOTEQUAL INT_SLESS INT_SLESSEQUAL INT_LESS INT_LESSEQUAL` |
| int arith | `INT_ADD INT_SUB INT_MULT INT_DIV INT_SDIV INT_REM INT_SREM INT_2COMP` |
| int bitwise | `INT_NEGATE INT_XOR INT_AND INT_OR INT_LEFT INT_RIGHT INT_SRIGHT` |
| int width | `INT_ZEXT INT_SEXT PIECE SUBPIECE` |
| flags | `INT_CARRY INT_SCARRY INT_SBORROW` |
| bool | `BOOL_NEGATE BOOL_XOR BOOL_AND BOOL_OR` |
| float | 19 ops, `FLOAT_ADD` … `FLOAT_ROUND` |
| **SSA** | **`MULTIEQUAL`** (phi-node), `INDIRECT` |
| **types** | **`CAST PTRADD PTRSUB`** |
| misc | `SEGMENTOP CPOOLREF NEW INSERT ZPULL SPULL POPCOUNT LZCOUNT` |

Three of these are the difference between assembly-with-C-syntax and real
pseudocode, and Hex-Rays does not expose equivalents:

- **`MULTIEQUAL`** — an explicit SSA phi node. SSA is *in the IR*, not bolted on.
- **`PTRADD`** — array indexing, `base + index*stride`, as one operation.
- **`PTRSUB`** — struct field access, `base -> field`, as one operation.

`PTRADD`/`PTRSUB` matter enormously for our target. Siege reverse-engineering is
almost entirely "which field at which offset of which struct" — an IR that
represents field access natively turns `*(QWORD*)(rcx + 0xD8)` into
`entity->components` as a *structural* result rather than a naming convention.

## 136 simplification rules — the readability engine

`ruleaction.hh` declares 136 named `Rule*` classes; `ruleaction.cc` is 11,017
lines implementing them. Each is a small, independently-testable pattern
rewrite. A sample:

```
CollectTerms  SelectCse  Piece2Zext  Bxor2NotEqual  OrMask  AndMask
OrCollapse  AndOrLump  NegateIdentity  ShiftBitops  RightShiftAnd
IntLessEqual  Equality  TermOrder  PullsubMulti  PushMulti
NotDistribute  AndDistribute  RangeMeld  AndCommute  AndPiece  AndZext
DoubleSub  DoubleShift  ConcatShift  LeftRight  ShiftCompare  TrivialArith
TrivialBool  ...
```

**This is the part you cannot derive from a header, and it is why Ghidra output
is readable.** Raw lifted IR is verbose and ugly; these rules are what collapse
it.

Directly relevant to Siege: this project fights **MBA (mixed boolean-arithmetic)
obfuscation**, and rules like `AndOrLump`, `NotDistribute`, `AndDistribute`,
`NegateIdentity`, `TrivialBool`, `CollectTerms` are general algebraic
simplifiers over exactly that algebra. The existing `src/crypto/mba.cpp` is 50
lines — a placeholder. A rule engine of this shape is the real answer, and the
implementations are right here to study.

## Control-flow structuring: `CollapseStructure`

`block.hh` defines the structured block types:

```
BlockBasic  BlockList  BlockCopy  BlockGoto  BlockMultiGoto
BlockCondition  BlockIf  BlockWhileDo  BlockDoWhile  BlockInfLoop
BlockSwitch  BlockMap  BlockGraph
```

`blockaction.cc` implements the algorithm as iterative pattern collapse — each
rule recognises one shape in the CFG and replaces it with a structured node:

```
ruleBlockCat        sequence      ruleBlockWhileDo    while loop
ruleBlockOr         || chain      ruleBlockDoWhile    do/while
ruleBlockProperIf   if            ruleBlockInfLoop    infinite loop
ruleBlockIfElse     if/else       ruleBlockSwitch     switch
ruleBlockGoto       goto          ruleCaseFallthru    case fallthrough
ruleBlockIfNoExit   if(noreturn)
```

Repeat until nothing collapses; whatever will not collapse becomes a `goto`.
That last property is what makes it robust on obfuscated control flow — it
degrades to `goto` rather than failing.

## The largest sources, and what each is for

| file | lines | what |
|---|---|---|
| `ruleaction.cc` | 11,017 | the 136 simplification rules |
| `fspec.cc` | 5,976 | function prototypes, calling conventions |
| `coreaction.cc` | 5,798 | the pass pipeline |
| `type.cc` | 5,161 | type system |
| `subflow.cc` | 4,131 | sub-variable / bitfield flow |
| `block.cc` | 3,723 | CFG and structured blocks |
| `printc.cc` | 3,536 | C output |
| `database.cc` | 3,427 | symbol/function database |
| `jumptable.cc` | 2,880 | switch/jump-table recovery |
| `heritage.cc` | 2,872 | **SSA construction** |
| `typeop.cc` | 2,625 | per-opcode type rules |
| `rangeutil.cc` | 2,605 | value-range analysis |

`heritage.cc` (SSA) and `jumptable.cc` (indirect jump recovery) are both hard
problems solved here, and both are directly needed.

## What this changes

Combined with the IDA SDK, the decompiler stops being the risky part:

1. **Adopt P-code, not Hex-Rays microcode.** Nearly the same size, but with SSA
   (`MULTIEQUAL`) and pointer arithmetic (`PTRADD`/`PTRSUB`) in the IR. Better
   suited to structure recovery, which is the actual job here.
2. **Port simplification rules incrementally.** They are independent. Ten rules
   give noticeably better output; all 136 is a long tail we may never need.
3. **Use `CollapseStructure` wholesale.** The algorithm is simple, published,
   and degrades gracefully to `goto`.
4. **`ruleaction.cc` is the MBA answer.** Replace the 50-line placeholder with a
   real rule engine modelled on this.
5. **Reference `heritage.cc` for SSA** rather than deriving phi placement.

## Licensing

Ghidra is Apache 2.0 — permissive, allows derivative works. The IDA SDK is
Hex-Rays proprietary and must be treated as **reference only**: read it to
understand the architecture, do not copy code from it. Ghidra is the one we can
actually borrow from.
