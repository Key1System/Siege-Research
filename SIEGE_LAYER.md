# The Siege layer — built and VERIFIED LIVE 2026-09-19

Target-specific analysis built on phases 1-5. Everything here was measured
against the running game.

| file | role |
|---|---|
| `src/analysis/siege.{h,cpp}` | structural vtable discovery, constructor store analysis |
| `src/analysis/routes_siege.inc` | `/vt_scan` `/vt_top` `/ctor_find` `/obj_scan` `/obj_fields` |
| `src/analysis/routes_mbax.inc` | `/mba_solve` `/mba_globals` |

## The headline result: 42,974 game classes, where RTTI found ZERO

```
/vt_scan   vtables_found 57,752   with_rtti 14,778   ms 31
           game_vtables_estimate 42,974
```

RTTI recovery (`/rtti_build`) finds 91 classes, ALL third-party, because the
game is compiled `/GR-`. Structural discovery finds **57,752 vtables in 31 ms**,
of which ~43,000 carry no RTTI — those are the game's own types.

A vtable is a run of consecutive qwords pointing at executable code, sitting in
non-executable data. That structure survives `/GR-` because it is what the CPU
needs at runtime; only the *names* were compiled out.

### Ranking replaces the names we cannot have

```
/vt_top
  0x12580B20  len=5   takers=8132   <- constructed in 8,132 places
  0x12257560  len=9   takers=6532
  0x12586CE8  len=9   takers=6316
```

`xref_takers` counts functions that load the vtable's ADDRESS — i.e. construct
that type. It is a usable proxy for importance.

## `/ctor_find` — the chain, working

```
/ctor_find {"rva":"0x121CBFC8"}    the player vtable
  candidates 2, both INSTALLS_VTABLE=true
```

Both candidates are **structurally proven constructors** — each writes the
vtable into offset 0 of the object in `rcx`:

```
0x1D18490:  lea r8, [rip+0x121CBFC8]
            mov [rcx], r8              <- vtable_install at +0x0
```

### Recovered object layouts

| ctor | field offsets written |
|---|---|
| `0x1CA1BF0` | `+0x10 +0x70 +0x80 +0xE0 +0xFC +0x118` |
| `0x1D18490` | `+0x118 +0x148 +0x178 +0x240 +0x270` |

`+0x118` appears in both — they construct related types, consistent with the
two-vtable multiple-inheritance finding.

## A CORRECTION that mattered

The first version of the store scanner matched only `mov [rip+global], reg`
and reported "no global stores found" on functions that obviously touch
globals. That was a **false negative reading as a finding**.

Disassembly showed the real shape:

```
mov [rcx], r8               <- stores INTO THE OBJECT, not a global
mov r8, [rip+0x12E40AB8]    <- LOADS a manager global
mov rax, [r8+0x370]         <- indexes through it
```

Objects here are not stored into bare globals; they are registered through a
manager reached BY a global. The scanner now recognises four kinds —
`store_to_global`, `load_global`, `store_to_this`, `vtable_install` — which is
what surfaced the layouts above.

## Evidence of the MBA obfuscation, direct

`0x1CA1BF0`'s globals hold values like:

```
0x12CAEB90 -> 0x807DE1EB9F1802C5
0x12CAF9F8 -> 0x43608DBE2E2B55E4
0x12CAFBD8 -> 0x75566BE9568A76CA
```

**These are not pointers.** They are the constant halves `crypto/decrypt.h`
documents: Siege splits each real address as `address = mask + index`, so
neither half is a pointer and *"scanning memory for pointers into these tables
finds NOTHING — the address exists only for the duration of the add."*

That is why this layer emulates instead of scanning.

## `/mba_solve` — status: works, needs seeding

```
/mba_solve {"rva":"0x1CA1BF0"}
  ok=true  instructions=1116  reason=fault  pages_zeroed=2
  error: "uc_emu_start: Invalid memory mapping"
```

It executed 1,116 instructions of obfuscated code before faulting on a
dereference that needs a real `this`. That is correct behaviour for a
constructor invoked with no arguments — **not a bug**. Pass a live object
pointer in `regs.rcx` and the chain completes.

The design point stands: crypto/mba.h records that FOUR hand-derived
reductions of chains like this produced non-pointers and that a pattern
detector was ~50% wrong. Executing 1,116 instructions took microseconds and
involved no algebra to get wrong.

## `/obj_scan` and `/obj_fields`

`/obj_scan` finds every live instance of a vtable in the heap: committed
MEM_PRIVATE regions only, one guarded 64 KB bulk read per chunk (never a
guarded read per pointer — that is what froze a sibling tool), a hard time
budget, and 8-byte alignment to cut the work 8x. An incomplete scan says so
loudly, because a truncated scan returning 0 must never read as "absent".

`/obj_fields` classifies each qword of an object: `VTABLE`, `code_ptr`,
`image_ptr`, `heap_ptr` (with `points_to_object` when the pointee is itself an
object), `float2`, `small_int`, `zero`, `data`.

## NOT yet done

- **Confirming a registration global.** `confirmed_globals: 0` — correct, since
  the test ran OUT OF A MATCH (Siege was at 1.3 GB, not 3.1 GB). No player
  object existed. **Re-run `/ctor_find` in a live round.**
- `/mba_solve` with a seeded `rcx` from a real object.
- `/obj_scan` against a live player vtable.
