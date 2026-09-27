# Phase 2 — the cross-reference index — BUILT, NOT YET VERIFIED LIVE

Date: 2026-09-19. Siege was not running when this was written, so **every
number below is a design expectation, not a measurement.** Phase 1's doc
separates those two carefully; this one has to as well, and right now it is
entirely in the second category.

## What exists

| file | role |
|---|---|
| `src/analysis/xref.h` | `xref_t`, `xref_kind`, `xref_stats_t`, `XrefDb`, `xdb()` |
| `src/analysis/xref.cpp` | the sweep, the two sorted orderings, the queries |
| `src/analysis/routes_xref.inc` | `/xref_build` `/xref_to` `/xref_from` `/xref_callers` `/xref_stores` `/xref_stats` |

Wired into `src/ipc/server.cpp` and `CMakeLists.txt`. **Builds clean**
(`BytecodeInternal.dll`, 11,352,576 bytes, 2026-09-19 12:42).

## What it does

Sweeps every function in the phase-1 database, decodes its body, and records
every reference it makes. Five kinds, kept distinct:

| kind | instruction | why it is its own kind |
|---|---|---|
| `call` | `call <rel32>` | the call graph |
| `jmp` | `jmp`/`jcc <rel>` | intra-function flow and tail calls |
| `rip_mem` | `mov rax,[rip+d]` | **reads/writes** a global |
| `rip_lea` | `lea rax,[rip+d]` | **takes the address of** a global |
| `imm` | `mov rax,<abs64>` | a materialised absolute pointer |

`rip_lea` vs `rip_mem` is the distinction the whole index turns on. See
`/xref_stores` below.

## Why the sweep is function-driven and not linear

A linear disassembly has to guess where instructions start. Guess wrong once —
on a jump table, on inline data, on padding — and everything after it is
garbage until it accidentally resynchronises. That garbage decodes into
plausible calls to plausible addresses, and those fabricated edges are
**indistinguishable from real ones** once they are in the index.

We do not have to guess. The exception directory states where every non-leaf
function begins. Starting each run at a linker-declared boundary means the
first instruction certainly is one.

The cost is the ~18.7% of `.text` the directory does not describe. Those bytes
produce no edges. That is the right trade: **a missing edge is a gap you can
measure and report; a fabricated edge is a wrong answer you cannot detect.**

On an undecodable byte mid-function the sweep stops that function rather than
resyncing, for the same reason.

## What it deliberately cannot do

Indirect control flow (`call rax`, `jmp [rcx+8]`) has no static target. It is
**counted, never guessed** — `indirect_calls` / `indirect_jmps` in
`/xref_stats`.

This matters more than it sounds. In a C++ binary most calls are virtual, so a
consumer treating this as a complete call graph will be wrong about
reachability nearly everywhere. `/xref_stats` returns a `completeness_note`
saying so in the response itself, rather than leaving it in documentation
nobody reads at 2 a.m.

## `/xref_stores` — the route this was built for

A C++ constructor installs a vtable by loading its address and storing it:

```
lea  rax, [rip + <vtable>]      <-- a rip_lea edge to the vtable
mov  [rcx], rax                 <-- the store
```

So **"who constructs objects of this class" reduces to "which code takes the
address of this vtable"** — a `rip_lea` or `imm` edge, not a `call` and not a
`rip_mem` read. Filtering to those two kinds is what separates the handful of
constructors from thousands of ordinary uses.

That is the intended path to the open `r6-internal` problem: point it at the
player vtable RVA `+0x121CBFC8`, get the constructor, read which global the
object registers itself into, and replace the multi-GB heap sweep with a
pointer read.

`/xref_stores` also reports `other_kind_refs`, so a zero result is
interpretable — "nothing references this" and "many things do but none take
its address" are different findings with different next steps.

## CORRECTION (same day) — target arithmetic delegated to Zydis

The first version hand-computed every target as `rva + length + disp`. An
audit against the vendored `Zydis.h`/`Zydis.c` established two things:

**The arithmetic was right.** `ZydisCalcAbsoluteAddress` (Zydis.c:122771) does
exactly `runtime_address + instruction->length + disp`, and `length` is the
FULL instruction length including any trailing immediate — so the awkward
`mov [rip+d], imm32` case was never wrong.

**But one filter was.** The `imm` kind accepted *any* non-relative 64-bit
immediate landing in the image range. That turns arithmetic constants into
fabricated edges — `add rax, 0x1400000` is not a reference to anything. Zydis
exposes `imm.is_address`, the decoder's own judgement about whether an
immediate is an address, and `ZydisCalcAbsoluteAddress` refuses immediates
without it. **Now gated on `is_address`.**

Both paths now call `ZydisCalcAbsoluteAddress`, passing the address of the
instruction ITSELF (the library adds `length` internally — passing the next
instruction would double-count). That also picks up cases the hand-rolled
version did not handle at all: EIP-relative bases, absolute `[disp32]` with no
base or index, and operand-width truncation.

Re-deriving x86 addressing by hand is how you get an answer that is right on
the instructions you tested and wrong on the ones you did not.

Also confirmed by the same audit: `ZYDIS_MAX_OPERAND_COUNT` is **10**, not the
5 of `..._VISIBLE`, and `ZydisDecoderDecodeFull` writes `operand_count`
entries — all operands, hidden included. Every operand array in this codebase
was already sized correctly; no change needed, but a 5-element array here
would have been a stack overflow.

## Safety properties

- **Time-sliced.** `budget_ms` defaults to 4000 and is clamped to [50, 30000].
  On expiry the sweep stops at a function boundary and returns
  `complete:false` with `resume_at`; `{"resume":true}` continues. A sibling
  project held a lock across a multi-second sweep and made the DLL
  unresponsive and unloadable — that cost a game restart, so this was built
  interruptible from the start rather than retrofitted.
- **A partial index is never published.** If the budget expires the edges are
  not sorted and `ready()` stays false, so queries refuse rather than return
  silently incomplete answers.
- **One guarded bulk read per function body**, decoded out of our own buffer —
  Zydis has no SEH guard of its own (see `disasm.h`), and 340k individually
  guarded reads is the `__try`-frame mistake already paid for once here.
- Read-only throughout. No writes, no hooks.

## Expected shape — TO BE CONFIRMED, NOT MEASURED

| quantity | expectation | basis |
|---|---|---|
| edges | 4–7 M | ~245 MB swept, an edge every ~40–60 bytes of code |
| index memory | ~100–170 MB | `edges x 12 B x 2 orderings` |
| full sweep | 2–8 s | needs 1–3 `/xref_build` calls at the default budget |
| decode_failures | non-zero, small | jump tables inside function bodies |

**If `decode_failures` is large (>5% of functions), stop and investigate
before trusting any query** — it would mean the bodies are not what the
directory claims, which changes the meaning of every edge.

## First live checks, in order

1. `POST /func_db` — confirm the phase-1 oversize fix first:
   `lookup_table=340481`, `oversize_held=10`.
2. `POST /func_at {"rva":"0x14600000"}` — must now be `found:false`.
3. `POST /xref_build {}` — repeat with `{"resume":true}` until
   `complete:true`.
4. `POST /xref_stats` — sanity-check the four quantities above.
5. `POST /xref_to {"rva":"0x41E870"}` — `Reflex::GetTransforms`, known-good
   from phase 1. It is called by real code, so a `call` count of 0 here means
   the index is broken, not that the function is unused.
6. `POST /xref_stores {"rva":"0x121CBFC8"}` — the actual objective.

Step 5 is the honest test. Steps 1–4 only prove the sweep ran.
