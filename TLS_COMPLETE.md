# The complete TLS map — every slot, site, thread and routine

Measured live 2026-09-19, Siege pid 21800, base `0x7FF6279D0000`.

## Headline

```
POST /tls_build     13 s total (2 passes)
  block_size          0x1C910   (14,624 qword slots)
  tls_index           0
  functions_with_tls  101,229 of 340,481
  instructions        53,010,332
  sites               489,529
  slots_touched       12,615
  KEY SLOTS           9,350
  stores              164,076
  threads             87
  index               16.8 MB

POST /tls_templates 52 s
  routines extracted  14,843
  slots with a routine 7,727
```

The old `/tls_map` took **75 seconds** and emitted 4,000 of 10,673 slots. This
does 12,615 slots with full site lists in **13 seconds**, because it rides the
same single decode pass the xref sweep uses instead of byte-pattern scanning
with hand-tuned windows.

## THE RESULT THAT MATTERS FOR DECRYPTION

```
slots_per_thread : 51   of 12,615
```

**Only 51 slots hold different values in different threads.** 99.6% of TLS
values — including every crypto key checked — are IDENTICAL across all 87
threads, so they can be read from the HTTP worker's block.

That matters because `tls.h` warns at length that the worker's block is not a
game thread's, and the honest-but-unmeasured assumption was that keys might
be per-thread. Measured: they are not.

The 51 that DO vary are all low-offset bookkeeping — `0xA`, `0xB`, `0xC`,
`0x10`, `0x18`, `0x6B8`, `0xAC0`, `0xAD8`, `0xB28`, and a few above `0x6158`.
Their verdicts are `counter`, `pointer`, `compare`, `store`. None is a crypto
key. `/tls_slot` flags any such slot with an explicit `key_warning`.

## Ground truth: slot 0x9800 (the T7 key)

```
POST /tls_slot {"offset":"0x9800"}
  verdict    sub-key        sites 25   funcs 6   key_sites 22
  roles      sub-key 13, add-key 7, xor-key 2, compare 2, copy-out 1
  template   0xA0E95BCA8E6D268F
  worker     0xA0E95BCA8E6D268F     mutated false
  threads_seen 64   threads_mutated 0   distinct_values 1
```

`crypto/decrypt.h` documents T7 as `ROL64(enc,4) - TLS[0x9800]`, derived by
hand. This independently confirms 0x9800 is a **sub-key**, used 22 times as a
key across 6 functions, with a value identical in all 64 sampled threads.

Note `multi_use: true` — the same slot is also an add-key and an xor-key
elsewhere. A majority verdict alone would have reported only "sub-key" and
hidden the rest, which is why `role_counts` is published per slot.

## Role histogram (12,615 slots)

| role | slots |
|---|---|
| load-only | 4,370 |
| **sub-key** | **2,964** |
| **xor-key** | **1,896** |
| **rot-count** | **1,441** |
| **add-key** | **1,144** |
| copy-out | 298 |
| mask | 190 |
| pointer | 116 |
| store | 106 |
| compare | 46 |
| counter | 44 |

`load-only` means the value was read but the consumer was not seen — the
trail was lost to a branch or a call. Reported as its own role rather than
guessed at.

## The crypto surface, collapsed

Every polymorphic encoding normalises to an operation sequence. The whole
surface is a readable list:

| count | routine shape |
|---|---|
| 1767 | `LOAD,SUB@TLS` |
| 736 | `LOAD,ROL#imm,SUB@TLS,XOR` |
| 665 | `LOAD,SUB,ROR@TLS,SUB@TLS` |
| 532 | `LOAD,SHR` |
| 508 | `LOAD,ADD` |
| 504 | `LOAD,XOR` |
| 501 | `LOAD,ROR@TLS` |
| 501 | `LOAD,XOR@TLS` |
| 486 | `LOAD,SUB@TLS,ROR@TLS` |
| 466 | `LOAD,XOR,SUB@TLS` |
| 438 | `LOAD,XOR,ROR,ADD@TLS` |
| 396 | `LOAD,ROL#imm,SUB@TLS,ROR@TLS` |
| 373 | `LOAD,SUB,ROR,SUB@TLS` |
| 360 | `LOAD,SUB@TLS,ROR@TLS,ADD@TLS` |
| 330 | `LOAD,ADD@TLS`, `LOAD,XOR,ROR,XOR@TLS` |
| 320 | `LOAD,XOR,SUB@TLS,XOR` |
| 304 | `LOAD,ROL#imm,ADD@TLS` |
| 265 | `LOAD,ROR@TLS,SUB@TLS` |
| 242 | `LOAD,AND#imm` |
| 241 | `LOAD,XOR,ROR@TLS,ADD@TLS` |
| 240 | `LOAD,ROR@TLS,ADD@TLS,XOR@TLS` |

**Multi-key routines are real and handled** — `SUB@TLS,ROR@TLS,ADD@TLS`
consumes THREE distinct TLS keys. A decryptor built on one key produces
garbage on those fields, which is why every routine lists all its slots.

Example with a working inverse:

```
fwd: ((ROR64(enc, TLS[0x228]) + TLS[0x1C0]) + 0x8) ^ reg
inv: ROL64((((plain ^ ?) - 0x8) - TLS[0x1C0]), TLS[0x228])
```

## What the sweep catches that byte patterns miss

- **direct-memory keys** — `sub r10,[r12+0x9800]`, where the key never lands
  in its own register. A scanner looking for a load then a sub sees nothing.
- **transformed keys** — the key is rotated or complemented before use; the
  link to its slot survives via a `key_transformed` flag rather than being
  dropped.
- **copy-propagated keys** — the value moves through two or three registers
  before being consumed.
- **rotate counts in CL** — tracked separately, because the count register is
  not the shifted register (this is the T8 template).

## Known imperfection, stated

Routine templates are attributed to a slot via its key SITES, and the
backward resolver is straight-line only. Consequence seen live: slot `0x90`
(verdict `store`, value 0) carries a template reading `enc + TLS[0x90]`,
inherited from a neighbouring site. Templates are evidence, not proof —
`complete:false` and `?` markers show where the resolver gave up rather than
guessing, and `/rt_verify` emulates a site to check a formula against what the
game actually computes.

Of 14,843 routines, those marked `complete:true` had every operand resolved.

## Routes

| route | purpose |
|---|---|
| `/tls_build` | the sweep (time-sliced, resumable) |
| `/tls_summary` | whole picture: roles, shapes, per-thread counts |
| `/tls_slots` | slot table; filter `keys_only`, `role`, `mutated_only` |
| `/tls_slot` | ONE slot: values, every site, every routine, per-thread values |
| `/tls_templates` | extract routines for key slots (resumable) |
| `/tls_threads` | every thread's block; optionally one slot across all |
