# In-process analysis engine — the numbers that constrain the design

> ## ⚠️ CORRECTED 2026-09-18 — see `PHASE1_STATUS.md`
>
> Two claims below are WRONG and are kept only so they are not re-derived:
>
> * **`.pdata` is NOT at RVA `+0x14014000`.** That section header is a DECOY
>   the packer left behind; its contents are ciphertext. The real exception
>   directory is at PE `DataDirectory[3]` = RVA **`0x1AF7B320`**, measured live.
> * **The entry count is 340,491, not 340,650.** The 340,650 figure was computed
>   from the decoy section's size.
>
> Everything else here (index sizing, decode cost, live-process advantages)
> still holds. Phase 1 is built and verified: 340,491 functions in 498 ms.


Computed from the verified segment map, not estimated. Anything built here
should be sized against these rather than against intuition.

## The target

| segment | RVA range | size | note |
|---|---|---|---|
| `.text` | `+0x00001000`..`+0x11FAF000` | **288 MB** | main code |
| `.rdata` | `+0x11FAF000`..`+0x12BDD000` | 12 MB | vtables, strings live here |
| `.data` | `+0x12BDD000`..`+0x14014000` | 20 MB | globals |
| `.pdata` | `+0x14014000`..`+0x143FA000` | 3.9 MB | **unwind info** |
| `.tls` | `+0x14401000`..`+0x1441E000` | 116 KB | crypto keys |
| `.UBX0` | `+0x1442E000`..`+0x145D0000` | 1.6 MB | CODE, unexamined |
| `.UBX1` | `+0x145D0000`..`+0x1B361000` | 109 MB | CODE, unexamined |

Total code to cover: **399 MB**.

## `.pdata` is the single biggest lever

`.pdata` holds `RUNTIME_FUNCTION` records — 12 bytes each: `BeginAddress`,
`EndAddress`, `UnwindInfoAddress`, all RVAs.

```
3,987,200 bytes / 12 = 340,650 entries
```

That is an **authoritative function list with exact boundaries**, supplied by
the linker. No recursive descent, no prologue heuristics, no guessing where a
function ends. (Independently corroborated: a prior IDA session on this binary
reported 304,472 functions.)

Consequences for the design:

- Function discovery is a **parse, not an analysis**. It should be the first
  thing implemented and it should take milliseconds.
- Every later stage (CFG, xrefs, decompilation) can be scoped to one function
  with known bounds, which makes everything demand-driven and cheap.
- Functions absent from `.pdata` (leaf functions with no unwind data, and
  anything in `.UBX*` if it is not covered) are the *exception* to handle, not
  the main problem.

## Index sizing at 340,650 functions

| table | count | per record | resident |
|---|---|---|---|
| functions | 340,650 | 20 B | 6.5 MB |
| basic blocks | ~3.4 M (est. 10/fn) | 16 B | 52 MB |
| xrefs | ~1.0 M (est. 3/fn) | 12 B | 11.7 MB |
| **core index** | | | **~70 MB** |

70 MB resident inside a game process is acceptable. Memory is not the
constraint.

## The real cost is decoding

Zydis decodes at roughly 100–200 MB/s per core. A full sweep of 399 MB is
therefore **2–4 seconds of CPU**.

That is fine as a background task and fatal as a synchronous one. The engine
must:

- chunk the work and yield, so the game keeps its frame rate;
- be abortable at a granularity far finer than one full pass — the r6-internal
  port already wedged a game once with an uninterruptible sweep;
- cache results keyed by RVA so a re-injection does not redo the work.

## What must never be cached across injections

Cache by **RVA**, never by absolute address. The image base changes every
launch, and a stale absolute is the failure mode that silently produces
confident nonsense — it has already cost this project several hours.

Heap addresses (entity lists, character objects, pose buffers) are
address-space-specific and must be re-derived every run.

## What a live process gives that a static dump does not

- Code is already decrypted and unpacked — the 111 MB of `.UBX*` is readable
  in situ.
- Indirect call targets can be **observed** with a hardware breakpoint rather
  than inferred. Observed edges are ground truth; static edges are hypotheses.
- Vtable pointers in live heap objects tie a concrete allocation to a concrete
  class, and the vtable in `.rdata` then yields the whole method set.
- Globals hold real values, so `(K1 + [global]) ^ K2` call targets resolve
  exactly instead of approximately.
- TLS is live and per-thread, making TLS-keyed crypto resolvable in situ.
