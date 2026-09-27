# SIEGE CRYPTO MAP — derived from scratch

**Date:** 2026-09-16
**Process:** `RainbowSix.exe` pid 25212
**Method:** everything below was derived live in this session through
`Bytecode-Internal` (in-process, read-only + sandboxed emulation).
Nothing is carried over from earlier notes. Where an earlier document
happens to agree, that is recorded as *independent corroboration*, never
as the source.

## Evidence rules

Every claim carries one of:

| tag | meaning |
|---|---|
| **DERIVED** | computed here from primary data (PE headers, live memory) |
| **MEASURED** | read directly out of the live process |
| **EMULATED** | produced by running the game's own code in a sandbox |
| **UNVERIFIED** | stated but not yet proven — do not build on it |

Nothing is written down because it sounds right. Two claims that were
*disproved* this session are recorded in §9 precisely so they are not
re-derived by accident.

---

## 1. Ground truth

**DERIVED** — from the PE headers, not from any tool's summary:

| field | value | how |
|---|---|---|
| image base | `0x7FF60FFA0000` | module base |
| `e_lfanew` | `0x78` | `[base+0x3C]` |
| PE signature | `PE\0\0` | `[base+0x78]` |
| SizeOfImage | `457,900,032` | `[NT+0x50]` |
| TLS dir RVA | `0x145F5CD0` size `0x1C958` | `DataDirectory[9]` |

**DERIVED** — IMAGE_TLS_DIRECTORY64 at `base + 0x145F5CD0`:

```
StartAddressOfRawData   0x7FF624595CF8
EndAddressOfRawData     0x7FF6245B2608
AddressOfIndex          0x7FF622D2030C
AddressOfCallBacks      0x7FF6245B2608
raw size                0x1C910   (117,520 bytes)
*AddressOfIndex         0          <- TlsIndex
```

Cross-check: the tool's own `/status` independently reports
`tls_raw = 0x7FF624595CF8`, `tls_size = 0x1C910`, `tls_index = 0`. Two
unrelated derivations, identical answers.

**The TLS block is reached as:**

```
tls = TEB->ThreadLocalStoragePointer[TlsIndex]      // TlsIndex == 0
key = *(uint64*)(tls + offset)
```

---

## 2. ⭐ The template equals the live block for every KEY

This is the single fact that makes external decryption possible, and it
is the one most worth getting right.

**MEASURED** — `/tls_verify` diffs the whole `0x1C910` block, PE template
versus a live thread's heap allocation:

```
differing slots: 51   of ~14,500
```

Every one of the 51 is in the low region (`+0x18`, `+0x40`, `+0x50`,
`+0x60`, …) and holds a **runtime pointer** initialised at startup.

**MEASURED** — slot-by-slot spot check:

| slot | template | live | verdict |
|---|---|---|---|
| `0x18` | `0x80000000` | `0x180000000` | **DIFFERS** — runtime state |
| `0x368` | `0x23` | `0x23` | identical |
| `0x9728` | `0x501FF8E9D66560C1` | identical | identical |
| `0x9738` | `0xC8BA7D90DAFC1409` | identical | identical |
| `0x9800` | `0xA0E95BCA8E6D268F` | identical | identical |
| `0x9850` | `0x4AC3DAA0B834A07B` | identical | identical |
| `0x98C8` | `0xDF278E286694709F` | identical | identical |

> **Conclusion: the crypto key block is NOT per-thread.** Keys can be
> read straight out of the PE image — no TEB walk, no thread
> enumeration, no breakpoints. The live block is a genuine per-thread
> heap allocation, so this is a real comparison and not the same memory
> read twice.

Note `TLS[0x18]` differing is itself evidence: whatever it is, it is
runtime state and therefore **not a static key**.

---

## 3. T7 — rotate-then-subtract — VERIFIED END TO END

**MEASURED** — the site is found by a byte signature that is still
unique in a 437 MB image:

```
signature   49 C1 C2 04 49 29 D2        rol r10,4 ; sub r10,rdx
hits        1
address     0x7FF61428B7D2
```

**EMULATED** — the decisive test. Rather than reimplementing the
formula, the game's own two instructions were executed in a sandbox with
a known input:

```
in   r10 = 0xFA0E95D4BDEC0FAF     (ciphertext)
     rdx = 0xA0E95BCA8E6D268F     (== TLS[0x9800], read from the template)
out  r10 = 0x1815053D470
trace      0x7FF61428B7D2 -> 0x7FF61428B7D6   (2 instructions)
```

The result is canonical, 8-byte aligned, and in the same heap band as
the objects this subsystem allocates.

**The formula, recovered from that behaviour:**

```
plain = ROL64(enc, 4) - TLS[0x9800]
```

What matters methodologically: **the emulator was told nothing about
ROL-4 or subtract-TLS.** It ran the instructions. Any template — known
or not — resolves the same way.

*Independent corroboration:* an earlier session computed
`0x1815053D470` by hand from a hardware-breakpoint capture. Same value,
different method, different build base.

---

## 4. The obfuscation is not one scheme

**MEASURED** — these are distinct mechanisms that are easy to conflate:

| # | mechanism | shape | external? |
|---|---|---|---|
| 1 | **TLS-keyed value crypto** | `ROL/ROR/SUB/XOR` against `TLS[k]` | ✅ yes |
| 2 | **MBA index arithmetic** | `(x^y)+2*(x&y)`, `(x\|y)+(x&y)` | ✅ yes (emulate) |
| 3 | **mask + index addressing** | address exists only during one `add` | ✅ yes (emulate) |
| 4 | **stack-hashed key selection** | index derived from live `RSP` | ❌ **no** |
| 5 | **opaque predicates** | low byte of a TLS slot decides a branch | n/a — not crypto |

Mechanism 4 is the only one an external process genuinely cannot
reproduce, because the index depends on the stack pointer at the call
site. Everything else yields to emulation.

Mechanism 5 is worth naming separately: it *looks* like crypto — a wide
TLS value feeding arithmetic — but nothing is decrypted with it. Treating
it as a key wastes time.

---

## 5. Why value-shape searching fails on gameplay fields

**MEASURED** — three independent statistical sweeps for health across
live entities, all empty:

| sweep | scope | result |
|---|---|---|
| entity bytes | 2 KB × 11 entities, u32/u16/float | nothing |
| per component | 16 kinds, single-value shapes | nothing |
| `{cur,max}` pair | 94 kinds, 6 gap sizes, `cur<=max`, max a base value | nothing |

**MEASURED** — the reason, visible in the field block of the richest
component class (kind `0x1E6`, vtable `0x7FF622101EA8`):

```
+0x014   E118DE3A E11911FC E118D0A2 E118D294 E118FCBA
+0x018   ED127D39 55127D39 01127D39 1D127D39 42927D39
+0x1B8   749CC17B 749CD17B 749CD17B 749CD17B 749CD17B
```

Each field shares a **constant half** across entities while the other
half varies per instance. That is a keyed field: one common key
component, one per-instance payload. A plaintext counter does not look
like this.

> A value-shape search cannot find an encrypted field, because the
> stored bytes are not the value. This is a property of the target, not
> a failure of the search — and running more variations of the same
> search will not change it.

---

## 6. Entity and component layout

**MEASURED** — an entity's components are addressed by a fixed table,
not by scanning:

```
entity + 0xD8    components[]        (pointer)
entity + 0xE0    count               (& 0x1FFFFFFF)
entity + 0x1D8 .. +0x238             component-KIND table, one byte each
                                     0xFF = no component of that kind
component = components[ byte_at(kind) ]
```

**MEASURED** — 33 component kinds resolve to a stable class vtable
across every live entity. Each kind is a constant offset, so every
component is reachable without searching.

| kind | vtable | methods |
|---|---|---|
| `+0x1E6` / `+0x1E7` | `0x7FF622101EA8` | **273** |
| `+0x1EE` | `0x7FF6220E64D8` | 108 |
| `+0x1F0` / `+0x237` | `0x7FF6225189A0` | 102 |
| `+0x1E3` | `0x7FF622277E78` | 96 |
| `+0x228` | `0x7FF622371A60` | 93 |
| `+0x1DD` / `+0x215` | `0x7FF6224A1B90` | 92 |
| `+0x214` | `0x7FF622415EA0` | 91 |
| `+0x229` | `0x7FF622466F10` | 66 |

`entity+0x229` is **not special-cased** — it is simply one slot in this
table, and it resolves to the class that owns the skeleton.

---

## 7. What the emulator replaces

Emulation removes the need to reimplement any of mechanisms 1-3.

| instead of | do this |
|---|---|
| reimplementing T7/T8/T9 | run the site, read the register |
| solving `mask + index` | run past the `add`, read the result |
| decoding an MBA index | run it; the identity is irrelevant |
| guessing an accessor's formula | call it with the object pointer |

**MEASURED** — the sandbox is faithful: emulated returns were compared
against direct reads of the same fields and matched exactly. So a wrong
answer from emulation means wrong *inputs*, not a wrong sandbox.

---

## 8. Not reproducible externally

**Stack-hashed key selection.** The key index is computed from the live
`RSP` at the call site, so an external reader cannot know it, and a
sandbox with a synthetic stack computes a *consistent but wrong* index.
This needs in-process execution at the real site.

---

## 9. Disproved this session — do not re-derive

Recorded so the same ground is not covered twice.

**The `0x0547481D` type hash is NOT a class identifier.** It appears on
**391 objects across 68 different vtables**. It is an engine-wide
component *family* tag. Any filtering that treats it as "the operator
avatar class" is unsound — the vtable is the class.

**`530`/`531` is not gameplay data.** It appears at many offsets in
nearly every component; it is a shared refcount. An unfiltered scan
returns ~148 "candidates" that are all this one value.

**A `/scan_aob` with `protection:"+X"` still returns non-module
addresses.** Results must be filtered to the module range explicitly, or
byte patterns matched in heap data will be mistaken for code.

**Stale entities invalidate everything downstream.** A sweep of 113
methods across 6 entities produced four textbook-looking `movzx eax,
byte [rcx+off]` accessors with plausible varying values — all of it read
from freed memory. Liveness must be re-verified *after* a run, not only
before; entity vtables decay to garbage within minutes.

---

## 10. Open

- Which component class owns health, and its accessor
- The full TLS slot classification (by consuming opcode, never by value shape)
- Whether RTTI survives in this build (class names for the 33 components)
