# RESUME HERE — state as of 2026-09-22
(measurements are from the 2026-09-19 live run; §0, §2, §7.2 and §9 were
corrected 2026-09-22)

Single entry point for picking this up cold. Everything below was measured,
not assumed; where something is unverified it says so.

---

## 0. READ THIS FIRST — NOTHING IN THIS REPO IS AUTOMATICALLY VERIFIED

*(state as of 2026-09-22; a fix is IN PROGRESS — see the end of this section)*

"VERIFIED" throughout this document means **a human read a live HTTP response
and judged it correct**. It does not mean a test asserted anything. Three
specific gaps, each checked today:

1. **`/rt_verify` does not verify.** Despite the name and its own comment
   ("EXECUTE the routine and compare"), it emulates and dumps registers.
   `src/analysis/routes_routine.inc:285-350`: it extracts the routine,
   runs the emulator from `rt.load_rva` to the last step, and emits
   `emu_out{rax,rbx,rcx,rdx,r8,r9,r10,r11}`. **There is no comparison
   anywhere in the handler** — the extracted formula is never evaluated, so
   there is nothing to compare the emulator against. The operator eyeballs
   the registers. A wrong routine and a right one produce the same
   response shape.

2. **There are ZERO tests in the repo.** `find . -iname "*test*"` returns
   nothing: no test file, no test directory, no test target.

3. **`mba.h:44`'s "Verified 4096/4096 on scattered inputs" harness is not in
   the repo.** The claim about the conditional identity
   `(X ^ K1) + 2*(X & K2) == X + K1` may well be true, but the code that
   established it does not exist here — grep for `4096` finds only unrelated
   buffer sizes and loop guards. The claim is unreproducible as written.

Note that (3) does **not** undermine the MBA results: `mbasolve.cpp` does not
rely on that harness. It proves the precondition per-site at runtime through
`proves_low_bits_clear()` (`mbasolve.cpp:112-134`), which is a stronger
guarantee than a batch of random inputs.

**IN PROGRESS:** another agent is adding `eval_routine` plus a real
comparison, which closes (1). Re-read this section before trusting it — if
`/rt_verify` now returns a match/mismatch field, that work has landed and
this note needs updating.

---

## 1. WHAT IS BUILT AND WORKING

**ALL SIX PHASES ARE BUILT AND VERIFIED LIVE.** See `LIVE_RESULTS.md` for the
measured numbers; that file is the authority on what actually works.

| phase | files | routes | status |
|---|---|---|---|
| 1 functions | `funcdb.{h,cpp}` | `/func_db /func_at /func_list /func_stats /func_oversize` | VERIFIED |
| 2 xrefs | `xref.{h,cpp}` | `/xref_build /xref_to /xref_from /xref_callers /xref_stores /xref_stats` | VERIFIED |
| 3 strings | `strings.{h,cpp}` | `/str_build /str_find /str_at /str_xref /str_stats` | VERIFIED |
| 4 CFG | `cfg.{h,cpp}` | `/cfg /cfg_dot` | VERIFIED |
| 5 imports | `imports.{h,cpp}` | `/imp_build /imp_resolve /imp_iat /imp_find` | VERIFIED |
| 5 RTTI | `rtti.{h,cpp}` | `/rtti_build /rtti_find /rtti_at /rtti_vtable /rtti_list` | works; see below |

Headline measured numbers: 340,481 functions; **11,495,588 xref edges** over
53M instructions in 9 s; 56,481 strings; 34,383 IAT slots 100% named; 91 RTTI
classes.

**The game stayed alive throughout, and `/ping` answered instantly during the
11M-edge sweep** — the fix for the lock bug that forced game restarts twice.

### TWO FINDINGS THAT CLOSE OFF WORK

1. **The game is built with `/GR-` (RTTI disabled).** All 91 recovered classes
   are third-party (STL, Microsoft glTF, rapidjson, Havok). There is no
   `Player`/`Entity` class to look up by name, and no parser improvement will
   create one. Full write-up: `PHASE5_RTTI_RESULT.md`.
2. **The game's own code is MBA-OBFUSCATED** — `xor`/`not`/`and` chains with
   64-bit magic constants, in **four forms chosen at random per site, which
   nest**. The tool for it is **`src/analysis/mbasolve.cpp`** (`/mba_at`,
   `/mba_solve`); it is built and has already solved a live site exactly.
   See `MBA_FORMS.md` and `LIVE_RESULTS.md`.
   (**Not** `src/crypto/mba.cpp`, and **not** `/deobfuscate` — see §7.2 for
   why that pointer was wrong.)

### THE ENGINE ANSWERED ITS MOTIVATING QUESTION

```
/xref_stores {"rva":"0x121CBFC8"}   the player vtable
  -> exactly 2 rip_lea takers out of 340,481 functions
     0x1CA1BF0 (MBA-obfuscated)   0x1D18490 (164 blocks, loads TWO vtables)
```

`0x1D18490` loading both `0x121CBFC8` and `0x121CBF08` is the signature of a
multiple-inheritance constructor. Its candidate registration globals are listed
in `LIVE_RESULTS.md`; `0x12E40AB8` was investigated and RULED OUT.

**`0x1CA1BF0` is NOT the second constructor** — it is a byte-stream
deserialiser. This document previously called it a "constructor candidate".
See §9, the retired-claims table, before spending any time on it.

### THE SIEGE LAYER — the answer to /GR- (see `SIEGE_LAYER.md`)

RTTI finds 91 classes, all third-party. **Structural vtable discovery finds
57,752 in 31 ms, ~43,000 of them the game's own.** `/vt_scan` `/vt_top`
`/ctor_find` `/obj_scan` `/obj_fields` `/mba_solve` `/mba_globals`.

`/ctor_find` on the player vtable returns 2 candidates, both with
`installs_vtable:true` — structurally proven constructors — plus their
recovered object layouts (`+0x10 +0x70 +0x80 +0xE0 +0xFC +0x118` and
`+0x118 +0x148 +0x178 +0x240 +0x270`).

**Run `/ctor_find {"rva":"0x121CBFC8"}` IN A MATCH.** It was tested out of one,
so `confirmed_globals` was 0 — correct, because no player object existed.

### SPECS — 415 KB of implementation-ready reference in `specs/`

`SPEC_STRUCTURING.md` (Ghidra's collapse rules + jump tables),
`SPEC_PCODE_IR.md` (all 75 opcodes, x86-64 lifting tables, SSA),
`SPEC_RTTI_VTABLE.md`, `SPEC_SIGNATURES.md` (update-resilient location),
`SPEC_HEAP_OBJECTS.md` (safe scanning), `SPEC_DECOMPILER_OUTPUT.md`.
All cite Ghidra file:line and flag their own inferences.

## 2. THE DECOY — the single most important fact

`.pdata` **by section name is a decoy** containing ciphertext. The section
header says RVA `0x14014000`; parsing it yields plausible garbage.

The real exception directory is at PE
`DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]` = RVA **`0x1AF7B320`**,
which physically lies inside `.UBX1`. Sizes differ (4,084,860 vs 4,085,892),
so they are not the same table relocated.

In a live process this cannot be wrong: the OS loader uses that field for
exception dispatch and the process has not crashed.

~~`mem.h::section_by_name()` still exists and will happily return the decoy —
the guard lives only in `funcdb.cpp`.~~
**FIXED 2026-09-22.** `mem.h::section_by_name()` now returns **false** for
`".pdata"` unconditionally, and the two real needs are separate, explicit
functions:

| want | call |
|---|---|
| the real unwind table (DataDirectory[3]) | `mem.h::exception_directory(base, out)` |
| the decoy ciphertext, deliberately | `mem.h::section_by_name_unchecked(base, ".pdata", out)` |

The refusal is unconditional even on an unpacked module: `section_by_name()`
cannot tell a packed image from a clean one, and a lookup that is right on
some targets and silently wrong on *the* target is worse than one that is
uniformly unavailable. The decoy is now documented in full, with both sizes,
in the block above `exception_directory()` in `src/core/mem.h`.

The only other `section_by_name()` caller in the tree is
`src/crypto/tls_map.cpp:504`, which asks for `".text"` — unaffected.

---

## 3. THE BUG FIXED TODAY (reproduced, then fixed, not yet re-verified)

`by_rva()` is "last begin <= rva, then `contains()`". Ten records exceed 1 MB;
record 8 spans `0x145EA174..0x1AE39144` — nearly all of `.UBX1`.

```
POST /func_at {"rva":"0x14600000"}
  -> found=true begin=0x145EA174 size=109375440     <-- WRONG
```

Every query inside that 109 MB range returned the blob instead of the real
function. Flagging them was not enough.

**Fix:** oversize records are moved to a separate list (`FuncDb::oversize()`)
after the sort so they cannot shadow lookups, and exposed via
`/func_oversize` rather than discarded. `/func_db` now reports
`lookup_table` and `oversize_held` separately. `build()` now clears
`m_oversize` too.

The 10 records, exact:

| RVA | size | segment |
|---|---|---|
| `0x14FF70` | 2,158,748 | .text |
| `0x7676D0` | 1,538,805 | .text |
| `0x2DB2DA0` | 1,314,710 | .text |
| `0x7E56420` | 22,071,297 | .text |
| `0x93F2C40` | 21,826,407 | .text |
| `0xF8450D0` | 1,097,305 | .text |
| `0x1448D879` | 1,317,371 | .UBX0 |
| `0x145EA174` | **109,375,440** | .UBX1 |
| `0x1A718616` | 7,474,112 | .UBX1 |
| `0x1AE395D3` | 1,317,323 | .UBX1 |

Sum 169,491,518. Records 8/9/10 overlap heavily; 10 ends 898 bytes before the
exception directory itself.

---

## 4. MEASURED TARGET FACTS

Image base `0x7FF708C90000`, size `0x1B4B0000` (457,900,032 B).
Three executable sections:

| name | begin | end | size | exec |
|---|---|---|---|---|
| `.text` | 0x1000 | 0x11FAE4F6 | 301,651,190 | yes |
| `.UBX0` | 0x1442E000 | 0x145CF3FE | 1,709,054 | yes |
| `.UBX1` | 0x145D0000 | 0x1B360BA4 | 114,887,588 | yes |

Function size distribution (all 340,491):

| bucket | count | % |
|---|---|---|
| 1–63 B | 28,893 | 8.49 |
| 64–255 | 149,094 | 43.79 |
| 256–1,023 | 116,910 | 34.34 |
| 1,024–8,191 | 42,551 | 12.50 |
| >=8,192 | 3,043 | 0.89 |

Coverage (oversize excluded): `.text` **81.3%** — so **~56 MB of `.text`
(18.7%) is NOT described** by the directory. `.UBX0`/`.UBX1` are essentially
undescribed (116.6 MB executable, 7,332 covered bytes). That gap is what a
recursive-descent / leaf-discovery phase would have to close.

---

## 5. API GOTCHAS (cost compile errors already)

- `js::value` has **no `has()`/`contains()`/`size()`**. Use the server-local
  helper **`present(v["key"])`** (`= !is_null()`). `routes_funcdb.inc`
  worked around this with a 0-sentinel before `present()` was known.
- No `as_uint` — cast: `(uint32_t)b["rva"].as_int(0)`.
- `js::object` is `std::map`, so **response keys emit alphabetically**.
- The JSON emitter has **no non-finite guard** — `NaN`/`inf` produce invalid
  JSON. Use integer permille instead of float ratios.
- `mem.h` **write primitives were deleted** (`write_raw`, `write_raw_force`,
  `write<T>`). The tool is read-only; `is_writable()` remains as a probe only.
- Zydis is **version 5**: `ZydisDecoderDecodeFull` is the **5-arg** form with
  a separate operand array. `ZydisDecodedOperand`'s `reg/mem/ptr/imm` is an
  **anonymous union** — check `op.type` before reading `op.mem`.
- `analyze.h::decode_run` stops at the first undecodable byte, **no resync**.
- **Use `ZydisCalcAbsoluteAddress` for every branch/RIP target** — do not
  hand-compute. Pass the address of the instruction ITSELF (it adds `length`
  internally). `ZYDIS_MAX_OPERAND_COUNT` is **10**; the `_VISIBLE` variant is
  5 and sizing an operand array with it overflows the stack.
- Gate `imm` references on **`op.imm.is_address`**. Accepting any 64-bit
  immediate in the image range turns arithmetic constants into fake edges.
- **Zydis 5 removed `op.mem.disp.has_displacement`** — this cost a compile
  error today. Presence is now `op.mem.disp.size != 0` (physical size in
  bits). The struct is `{ ZyanI64 value; ZyanU8 offset; ZyanU8 size; }`.
- A branch/call target resolves against the **NEXT** instruction
  (`insn_rva + insn.length + disp`), not the current one. Using the current
  one is off by `insn.length` and yields targets that still land in real
  code — wrong in the hardest way to notice.
- Heredocs: several of these files contain `'` inside comments, which breaks
  `bash <<'EOF'`. Use the Write tool or a Python heredoc for them.
- Routes already taken by `routes_disasm.inl`: `/disasm` `/func_range`
  `/xrefs_to` `/decompile` `/analyze_func` `/find_pattern_roles` `/trace_reg`
  `/callgraph`. A phase 2 wanting those names is **replacing**, not adding.

---

## 6. REFERENCE MATERIAL ON DISK

| doc | contents |
|---|---|
| `PHASE1_STATUS.md` | live results + the correction |
| `ANALYSIS_ENGINE_FACTS.md` | sizing; **header corrects its own wrong `.pdata` address** |
| `GHIDRA_ARCHITECTURE.md` | P-code 74 opcodes, 136 rules, `CollapseStructure` |
| `HEXRAYS_ARCHITECTURE.md` | microcode 73 opcodes, the 9-stage maturity pipeline |
| `AUDIT_FINDINGS.md` | 65 audited findings; **hwbp area had 52% refutation — distrust it** |

Ghidra source (Apache 2.0, borrowable):
`C:\Users\hhhuh\Downloads\ghidra-Ghidra_12.1.3_build\...\Decompiler\src\decompile\cpp`
IDA SDK (proprietary — **reference only, do not copy code**):
`C:\Users\hhhuh\Downloads\ida-sdk-main\ida-sdk-main\src\include`

---

## 7. NEXT STEPS, IN ORDER

1. **Finish the constructor hunt** — the one thing that closes the heap
   problem. Remaining candidate globals from `0x1D18490`: `0x12FA8888`,
   `0x12FA8930`, `0x12D8030C`. Read each IN A MATCH with characters spawned,
   then again out of a match; the one that changes holds entity state.
   (`0x12E40AB8` is already ruled out — do not redo it.)

2. **MBA: the right tool is `src/analysis/mbasolve.cpp`, and `0x1CA1BF0` is
   already DONE.**

   This step used to read: *"Point the existing MBA deobfuscator at
   `0x1CA1BF0`. `/deobfuscate` and `src/crypto/mba.cpp` already exist and are
   the right tools."* **Both halves of that were wrong**, and it would have
   sent the next person to two files that cannot do the job. Checked by
   reading them:

   - **`src/crypto/mba.cpp` is not a simplifier.** 50 lines, one function:
     `reduce_pair(a, b)` tries `a+b`, `a-b`, `b-a`, keeps whichever first
     lands in a readable module, and appends
     `"(ambiguous: more than one form was plausible)"` if more than one does.
     It is a 3-candidate brute force over a *live register pair*. Every
     identity declared in `mba.h:66-116` — `add_via_xor_and`,
     `sub_via_not_add_not`, `xor_expanded`, `fold_and_xor`,
     `add_via_or_and`, `sub_via_add_not` — is `inline` and **called by
     nothing**. Grep across `src/` finds only four prose mentions of
     `crypto/mba.h` in comments (`mbasolve.h:12`, `routes_mbax.inc:25`,
     `routes_mbax.inc:35`, `siege.h:22`) and zero call sites. The header is
     a good write-up of the algebra; it is not an implementation of it.
   - **`/deobfuscate` is a Unicorn emulator route**
     (`src/ipc/routes_emu.inl:332`). Its own comment says it "does not model
     the arithmetic at all — it runs the instructions and reads the register
     afterwards". It never touches `mba.cpp`. It is genuinely useful, just
     not as a simplifier.
   - **The real MBA simplifier is `src/analysis/mbasolve.cpp`** — symbolic
     arena, structural equality, and the soundness gate
     `proves_low_bits_clear()` at `mbasolve.cpp:112-134`. Routes `/mba_at`
     and `/mba_solve`.

   **And `0x1CA1BF0` has already been solved by it** —
   `/mba_at {"rva":"0x1CA1BF0","window":64}` returns `rsp + 0x5C3283C6`,
   `exact:true`, 4 steps (`MBA_FORMS.md:23-27`). That result is what
   reclassified the function (§9). Remaining MBA work is other sites, not
   this one; `/mba_globals` sweeps for them.

3. **String-anchored location is now the primary naming route** (RTTI is a
   dead end for game classes). `specs/SPEC_SIGNATURES.md` §4 designs a
   declarative locator that re-resolves every launch instead of storing
   offsets that break on patch day.

4. **Phase 6 — structuring/decompilation** when wanted:
   `specs/SPEC_STRUCTURING.md` and `specs/SPEC_PCODE_IR.md` are written to be
   implemented directly. Jump-table recovery (SPEC_STRUCTURING part B) would
   also close the CFG's `indirect_exits` blind spot.

## 8. THE SEPARATE, STILL-BROKEN PROJECT

`C:\Users\hhhuh\Downloads\r6-internal` is a different tool (ESP overlay). Its
status is in its own notes; the short version:

- Bones come from a hardware breakpoint whose buffer is **bind-pose data** —
  byte-identical across frames, no world position in it at all.
- The live pose comes from `Reflex::GetTransforms` (RVA `+0x41E870`), which
  writes the pose-buffer pointer into an **out-parameter**.
- `abstraction = [[character + 0x30] + 8]` — a pointer walk, NOT a fixed
  offset. (`+0xB8` was an allocator coincidence and cost three builds.)
- `character + 0x20 -> component`; the link only points that way, so the
  character must be searched for — currently a multi-GB heap sweep that has
  wedged the game more than once.

That last problem is exactly what step 7.2 above would solve.

---

## 9. CLAIMS THAT DID NOT SURVIVE — keep them dead

Same convention as `Siege-Research\00_START\README.md` §9: a ruled-out lead stays
on the page with its refutation attached, so it is not re-derived.

| claim | why it is wrong |
|---|---|
| `0x1CA1BF0` is the second player constructor (called a "constructor candidate" at §1 and in `LIVE_RESULTS.md`) | It is a **byte-stream deserialiser**. Read in full — 378 instructions: `movzx r10d, byte [rdx]` / `inc rdx`, buffer refill through `[rax+0x90]`, cursor/end/capacity at `r13+0x40 / +0x48 / +0x70`. `Siege-Research\06_internal_ida\VERIFIED.md:83`. Corroborated independently: `/mba_at` resolves it to `rsp + 0x5C3283C6`, `exact:true` (`MBA_FORMS.md:23-27`) — a **stack** address, which `mbasolve.cpp`'s gate `proves_low_bits_clear()` (`mbasolve.cpp:112-134`) only ever yields for `rsp`/`rbp` bases. A local stack buffer is what a deserialiser has; it is not what a constructor installing a vtable into a heap object has. |
| ~~follow `0x1CA1BF0`'s 8 calls to find a registration global~~ | **WITHDRAWN — do not do this.** It was step "unexamined" in `LIVE_RESULTS.md`. A deserialiser installs no vtable, so there is no registration global downstream of it. |
| `/deobfuscate` + `src/crypto/mba.cpp` are the MBA tools (old §7.2) | `/deobfuscate` is a Unicorn emulator route (`routes_emu.inl:332`); `crypto/mba.cpp` is a 50-line 3-candidate brute force and every identity in `mba.h:66-116` is dead code. The simplifier is `src/analysis/mbasolve.cpp`. See §7.2. |
| `0x12E40AB8` is the registration global | Holds `0x7FF63A815AE8` = `RainbowSix.exe+0x12E45AE8`, still inside `.data` 20 KB on, and its target is all zeros. A self-referential `.data` structure. (`LIVE_RESULTS.md`.) |

**Why `0x1CA1BF0` fooled us, and the lesson.** `/xref_stores` answered its
question correctly — that function really does `rip_lea` the player vtable at
`+273`. The error was the leap from *takes the address of a vtable* to
*constructs an object with it*. Code that deserialises a typed object
references the same vtable constant without being the constructor.
`/ctor_find` is the route that makes this testable, because it reports
`installs_vtable` structurally rather than inferring it from a reference —
prefer it over raw `/xref_stores` for this question.
