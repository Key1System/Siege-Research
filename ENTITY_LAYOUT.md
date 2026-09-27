# Live entity layout — MEASURED 2026-09-19, entities live

Siege pid 21800, image base `0x7FF6279D0000`. All of this was read out of the
running game with the Siege layer.

## The pool

`/obj_scan {"vtable_rva":"0x121CBFC8"}` -> **14,761 instances** (scan was still
incomplete at 4.69 GB / 10 s, so that is a floor, not a total).

They lie in a contiguous array at a uniform stride of **0x6A0 (1,696 bytes)**:

```
0x16922E1F0C0
0x16922E1F760   (+0x6A0)
0x16922E1FE00   (+0x6A0)
0x16922E204A0   (+0x6A0)
...
```

That is a POOL, not scattered allocations. Knowing the stride means the whole
set can be walked from one base pointer -- no repeated scanning.

## Verified object layout

| offset | kind | notes |
|---|---|---|
| `+0x00` | **vtable** | `0x7FF639B9BFC8` — identical across all entities |
| `+0x08` | **entity handle/ID** | `...DB05, DB04, DB02, DB00` — per-entity, decrementing |
| `+0x10` | masked field | see the cryptanalysis below |
| `+0x20`–`+0x68` | **transform** | identity-matrix floats (1.0/0.0 pattern) |
| `+0x80`–`+0x98` | **shared constants** | byte-identical across entities |
| `+0xA0`–`+0xB0` | per-entity state | differs between entities |
| `+0xB8` | shared constant | identical across entities |
| `+0xD8` | heap pointer | |
| `+0xE0`–`+0x100` | floats | `-2.0, 2.0` / `1.0, 1.0` — bounds or scale |
| `+0x118` | **second vtable** | RVA `0x1237E848` — the multiple-inheritance base |
| `+0x120`,`+0x128` | self-referential heap ptrs | `0x16922E1F1D8` — an intrusive list |

`+0x118` is exactly the offset the CONSTRUCTOR was measured writing
(`SIEGE_LAYER.md`), and it holds a vtable. Static and dynamic analysis agree.

## CRYPTANALYSIS of `+0x10` — it is not really encrypted

Four entities, XORed against the first:

```
0xE1075CBC0547481D   ^first = 0x0
0xE1075CB00547481D   ^first = 0x0C00000000
0xE1075CB80547481D   ^first = 0x0400000000
0xE1075CE00547481D   ^first = 0x5C00000000
```

**Every difference is confined to bits 32-39.** The low 32 bits
(`0x0547481D`) and the top 24 bits (`0xE1075C`) are IDENTICAL across all
entities.

So this is not a cipher over the whole qword -- it is a constant with a small
varying byte-field. Whatever mask is applied is FIXED, and XOR-differencing
two entities cancels it completely. Recovering the varying field needs no key
at all.

Corroboration: the low dword `0x0547481D` differs by 1 from
`0xC119C5400547481C`, which `crypto/decrypt.h` records as an MBA constant
observed in this build. Same constant family.

## `+0x80`-`+0x98` are shared, not per-entity

```
+0x80  0x398AB4797259D764   SAME across entities
+0x88  0x5F0C21A721EC2920   SAME
+0x90  0xEFAC7F8FC6486687   SAME
+0x98  0x1F952D0DB654489D   SAME
```

High-entropy AND identical means these are not encrypted per-entity data --
they are shared constants embedded in every object (mask halves, or a shared
key block). Do not waste effort trying to "decrypt" them per entity.

The genuinely per-entity fields are `+0x08`, `+0x10` (bits 32-39), `+0xA0`,
`+0xA8`, `+0xB0`.

## The manager chain, and why it is NOT the shortcut

`/ctor_find` returns `confirmed_globals: 0` EVEN WITH 14,761 LIVE OBJECTS.
That is a correct negative, and it is informative: these objects are **not
held in a bare global**.

The constructor's real access path, from disassembly:

```
mov r8,  [rip+0x12E40AB8]   ; the manager global
mov rax, [r8+0x370]         ; -> 0x169027E0000, a heap table
mov r11, r12
shr r11, 0x20               ; index by the entity ID's HIGH DWORD
mov rax, [rax+r11*8]
```

`[manager+0x370]` does hold a live heap pointer, but the table at its base
reads as all zeros -- it is SPARSE and indexed by `entity_id >> 32`, not
walked from offset 0. So the manager is a handle-resolution table, not an
enumerable list of entities.

**Conclusion: the pool stride is the better handle.** 14,761 objects at a
known 0x6A0 stride from a known base is directly enumerable; the sparse
handle table is not.

## One false positive worth recording

The scan's first hit, `0x4E29DFE170`, is NOT an entity. Its `+0x0` is a heap
pointer rather than the vtable, its address is in stack range, and it points
at `0x4E29DFE2xx` — it is a STACK FRAME that happened to contain the vtable
value at the matched offset.

This is exactly why `/obj_fields` exists: a raw value match is a candidate,
and checking that `+0x0` really is the vtable is what separates an object
from a coincidence.

## Next

- Read `+0xA0`/`+0xA8`/`+0xB0` across many entities while moving in-game to
  identify which is position/health/team.
- The transform at `+0x20`-`+0x68` is currently identity — re-read it for a
  MOVING entity to confirm it is the world matrix.
