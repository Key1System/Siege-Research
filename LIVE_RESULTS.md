# LIVE VERIFICATION — 2026-09-19, Siege pid 21800

Everything here was MEASURED against the running game, not estimated.
Image base this launch: `0x7FF6279D0000` (changes every launch — all values RVA).

## Phase 1 — functions — VERIFIED (and the pending fix confirmed)

```
/func_db   records_total 340,491   lookup_table 340,481   oversize_held 10
/func_at {"rva":"0x14600000"}  -> found:false            <- THE FIX, CONFIRMED
/func_at {"rva":"0x41E870"}    -> begin=0x41E870 size=2081 is_entry=true
```

The oversize shadowing bug that was outstanding from the previous session is
fixed and proven: `0x14600000` used to return a bogus 109 MB "function".

## Phase 2 — xrefs — VERIFIED, INCLUDING THE LOCK FIX

```
/xref_build  (3 passes, 9 s wall)
  edges            11,495,588
  instructions     53,010,332
  bytes_swept      241,700,968
  funcs_swept      340,471 / 340,481
  read_failures    0
  decode_failures  9,856      (2.9% — jump tables inside bodies, expected)
  indirect_calls   620,758    counted, never guessed
  indirect_jmps    38,483
  out_of_image     224
  index_bytes      342,978,300
```

**The game stayed alive and `/ping` answered instantly DURING the sweep.** That
is the fix for the audit's CRITICAL finding: the handler used to hold
`unique_lock<shared_mutex>` across the whole multi-second sweep AND both
11M-element sorts, which is what made the tool unresponsive and unloadable and
forced a game restart twice before. The sweep now runs under a dedicated
try-lock and takes the big lock only for the brief prerequisite parse.

### Correctness, tested where it could fail

```
/xref_to {"rva":"0x41E870"}          Reflex::GetTransforms
  total 1   by_kind {call:1, everything else 0}
  0x44B36CB  call  from_func=0x44B3610+187  .text
```

One exact caller for a known-good function. A wrong index would show zero
(broken) or hundreds (fabricating edges).

### THE QUERY THE ENGINE WAS BUILT FOR

```
/xref_stores {"rva":"0x121CBFC8"}    the player vtable
  matched 2, other_kind_refs 0
    0x1CA1BF0 + 273   rip_lea
    0x1D18490 + 19    rip_lea
```

**Two takers out of 340,481 functions.** This is the structural replacement
for r6-internal's multi-GB heap sweep.

> **CORRECTED 2026-09-22 — only ONE of these is a constructor.**
> `0x1CA1BF0` is a **byte-stream deserialiser**, not a constructor. See
> "RETIRED CLAIM" at the end of this file. `0x1D18490` still stands.

## Phase 4 — CFG — VERIFIED

```
/cfg {"rva":"0x1D18490"}
  size 3156  blocks 164  insns 728  calls 40
  cyclomatic 95  internal_edges 257  exit_edges 0
  indirect_exits 0  misaligned_targets 0
```

## Phase 5 — imports — VERIFIED

```
/imp_build   modules 157   exports 40,994
             iat_slots 34,383   iat_named 34,383  (100%)
             dir_present true   dir_trusted FALSE   ms 105
```

`dir_trusted:false` is the packer being caught: the declared import directory
disagrees with what a structural scan finds. The fallback (runs of consecutive
qwords pointing into loaded modules) is what named all 34,383 slots.

## Phase 5 — RTTI — WORKS, but see PHASE5_RTTI_RESULT.md

91 classes recovered in 546 ms, all validators behaving. **But every one is
third-party (STL / Microsoft glTF / rapidjson / Havok)** — the game itself is
built with `/GR-`. That is a permanent negative result, written up separately.

## NEW FINDING — the game's code is MBA-OBFUSCATED

Disassembling `0x1CA1BF0` (then believed a constructor; it is a
deserialiser — see RETIRED CLAIM below. The MBA finding itself is unaffected:
the obfuscation is real and is what made the function unreadable):

```
lea  r9,  [rsp+0x35B5F9A]
mov  rdx, r8
xor  rdx, 0xD706606
mov  r11d, r8d
and  r11d, 0xD706600
not  r9
lea  rdx, [rdx+r11*2]
mov  r11, 0x6D1B3FBF2EAB386B
add  r11, r9
mov  r9,  0xEC9DDDC9D3A5A441
xor  rdx, r9
not  r11
and  r11, r9
add  r11, r11
sub  r11, rdx
mov  r9,  [rax+r11*1]
```

That is **mixed boolean-arithmetic obfuscation** — `xor`/`not`/`and`/`add`
chains with 64-bit magic constants computing what is really a simple offset.
This explains the `cyclomatic:1` on a 2,011-byte function: it genuinely has no
branches, it is straight-line obfuscated arithmetic.

Consequences:
- **The MBA simplifier is `src/analysis/mbasolve.cpp`** (`/mba_at`,
  `/mba_solve`) — symbolic arena, structural equality, and the
  `proves_low_bits_clear()` soundness gate at `mbasolve.cpp:112-134`. It has
  already been run against this site successfully; see `MBA_FORMS.md`.
- **NOT `src/crypto/mba.cpp`.** That file is 50 lines and does one thing:
  `reduce_pair(a,b)` tries `a+b`, `a-b`, `b-a` and keeps whichever first
  lands in a readable module, appending
  `"(ambiguous: more than one form was plausible)"` when several do. It is a
  3-candidate brute force over a register pair, not a simplifier. Every
  identity declared in `mba.h:66-116` (`add_via_xor_and`,
  `sub_via_not_add_not`, `xor_expanded`, `fold_and_xor`, ...) is `inline` and
  **called by nothing** — verified by grep across `src/`: the only references
  to `crypto/mba.h` anywhere are four prose mentions in comments
  (`mbasolve.h:12`, `routes_mbax.inc:25`, `routes_mbax.inc:35`,
  `siege.h:22`). It is documentation of the algebra, not an implementation
  of it.
- **NOT `/deobfuscate`** either. That route is at `src/ipc/routes_emu.inl:332`
  and is a **Unicorn emulator** route — it runs the instructions and reads a
  register afterwards. It does not touch `mba.cpp` and deliberately models no
  algebra at all.
- `specs/SPEC_PCODE_IR.md` §D lists the Ghidra simplification rules that
  collapse exactly this kind of expression; `RuleSborrow` and the arithmetic
  identity rules are the relevant ones.
- The emulator (`src/emu/`, via `/deobfuscate`) can evaluate these chains
  concretely, which is often faster than simplifying them symbolically.

## What is still NOT verified

- `/str_build` and the string index — not yet run live.
- `/rtti_find` on game classes — cannot work; see the /GR- finding.
- The surviving constructor candidate `0x1D18490` (164 blocks, cyclomatic 95)
  has not been analysed for which global it registers into. **That is the next
  step, and it is the one that closes the heap problem.** (It is now the ONLY
  candidate — see RETIRED CLAIM.)


## Phase 3 — strings — VERIFIED

```
/str_build     total 56,481 (ascii 54,823 / utf16 1,658)
               bytes_scanned 39,758,229   ms 107   index_bytes 677,772
               rejected_short 4,321,696   rejected_score 48,847

/str_find {"q":"Reflex"}
  0x1271EA20  xrefs=1  "^GfxInfo.NvidiaReflex"
  0x1271EA36  xrefs=1  "disableNVReflex"
  0x12721C11  xrefs=1  "NVReflex. 0 : Disable, 1 : ReflexOn, 2 - ReflexWithBoost"
  0x127760EF  xrefs=1  "^GfxInfo.NvidiaReflexSupported"
```

Real strings with working xref counts — which also proves the phase-2/phase-3
JOIN works, since those counts come from the xref index.

## CONSTRUCTOR ANALYSIS — where this got to

`/xref_stores` on the player vtable `0x121CBFC8` gave exactly two candidates.
Investigating `0x1D18490` (164 blocks, 728 insns, 40 calls, cyclomatic 95):

**It loads TWO vtables:**
- `0x121CBFC8` — the known player vtable
- `0x121CBF08` — 192 bytes earlier, also `.rdata`

Loading two vtable addresses in one function is the signature of a constructor
for a class with MULTIPLE INHERITANCE. `0x121CBF08` is taken by four functions
(`0x1CA1BF0`, `0x1CC53A0`, `0x1CFEB80`, `0x1D18490`) — three of which overlap
with the `0x121CBFC8` takers. Strong evidence both are vtables of the same
class hierarchy.

**Globals the constructor touches** (from `/xref_from`, 194 refs total):

| global | hits | kind | segment |
|---|---|---|---|
| `0x12E40AB8` | 11 | rip_mem | .data |
| `0x128F72D0` | 5 | rip_mem | .rdata |
| `0x12FA8888` | 5 | rip_lea | .data |
| `0x12FA8930` | 5 | rip_lea | .data |
| `0x12D8030C` | 3 | rip_mem | .data |

### `0x12E40AB8` investigated and RULED OUT

It holds `0x7FF63A815AE8`, which looked like a live object pointer. It is not:
that address resolves to `RainbowSix.exe+0x12E45AE8` — still inside `.data`,
20 KB further on — and its target is all zeros. So `0x12E40AB8` is a
self-referential `.data` structure (a list head or allocator block), **not the
registration global**. Recorded because a plausible-looking pointer that is
NOT what you want is worth writing down once so it is not re-investigated.

### NEXT STEP — this is where to resume

The remaining candidates are `0x12FA8888`, `0x12FA8930` (both `rip_lea`, both
holding live-looking non-null data) and `0x12D8030C`. Read them in a MATCH,
with characters spawned, and compare against the same reads out of a match —
the one that changes is the one holding entity state.

~~Also unexamined: the other constructor candidate `0x1CA1BF0`, which is
MBA-obfuscated (see above) and whose 8 calls have not been followed.~~
**WITHDRAWN — do not follow those 8 calls.** `0x1CA1BF0` is not a
constructor and has no registration global to find. See below.

---

## RETIRED CLAIM — `0x1CA1BF0` is NOT a constructor

Kept, not deleted, so it is not re-investigated. This project's rule
(`Siege-Research\00_START\README.md` §9) is that a ruled-out lead stays on
the page with its refutation attached.

| claim | why it is wrong |
|---|---|
| `0x1CA1BF0` is a player constructor (a "constructor candidate" from `/xref_stores` on vtable `0x121CBFC8`) | It is a **byte-stream deserialiser**. Read in full — 378 instructions: `movzx r10d, byte [rdx]` / `inc rdx` (a byte-at-a-time cursor), buffer refill through `[rax+0x90]`, and cursor/end/capacity at `r13+0x40 / +0x48 / +0x70`. `Siege-Research\06_internal_ida\VERIFIED.md:83`. |
| its 8 calls lead to a registration global | There is no registration to find. A deserialiser reads bytes into a buffer; it installs no vtable. |

**Why the original inference was made, and where it broke.** `/xref_stores`
answers "which functions take the address of this vtable", and it answered
correctly: `0x1CA1BF0` really does `rip_lea` the vtable at `+273`. The leap
was from *takes the address of* to *installs it as the object's vtable*. A
deserialiser that reconstructs a typed object references the same vtable
constant without being the thing that constructs it. `/ctor_find` later made
this testable by reporting `installs_vtable` structurally rather than
inferring it from a reference.

**The corroborating measurement** (independent of reading the disassembly):

```
POST /mba_at {"rva":"0x1CA1BF0","window":64}
  expression : rsp + 0x5C3283C6      <-- a STACK address
  exact      : true    (every precondition PROVED)
  steps      : 4
```
(`MBA_FORMS.md:23-27`)

That `rsp` is load-bearing. `mbasolve.cpp`'s soundness gate
`proves_low_bits_clear()` (`mbasolve.cpp:112-134`) returns false for anything
that is not an `rsp`/`rbp`-based expression — it can only prove alignment from
the x64 ABI's 16-byte stack invariant. So `exact:true` is not a guess: the
solver *proved* the base is the stack pointer.

**A local buffer on the stack is what a deserialiser has. It is not what a
constructor installing a vtable into a heap object has.** Two independent
methods — reading 378 instructions, and a machine-checked symbolic solve —
agree, so this is settled.

**What survives:** the MBA finding above (the function really is
MBA-obfuscated, and it is the site `MBA_FORMS.md` verifies against), and
`0x1D18490`, which remains a genuine multiple-inheritance constructor
candidate.
