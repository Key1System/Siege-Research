# Phase 1 — BUILT, INJECTED, VERIFIED LIVE

Everything below was measured against the running game, not estimated.
Date: 2026-09-18.

## What exists now

| file | role |
|---|---|
| `src/analysis/funcdb.h` | `func_t`, `seg_t`, `parse_stats_t`, `FuncDb`, `db()` |
| `src/analysis/funcdb.cpp` | section parse + exception-directory parse |
| `src/analysis/routes_funcdb.inc` | `/func_db` `/func_at` `/func_list` `/func_stats` |

Wired into `src/ipc/server.cpp` (header at file scope, `.inc` inside the
anonymous namespace where the helpers live) and `CMakeLists.txt`. Builds clean.

## Live results

```
POST /func_db   ->  498 ms  (COLD first build; a warm rebuild measures ~9-17 ms)
  ok            : true
  dir_rva       : 0x1AF7B320        <-- NOT the .pdata section
  dir_size      : 4,085,892
  records_total : 340,491
  records_kept  : 340,491           <-- zero rejected
  rejected_range / rejected_noncode : 0 / 0
  chained       : 14,746
  oversize      : 10
  image_base    : 0x7FF708C90000
```

```
POST /func_at {"rva":0x41E870}      (Reflex::GetTransforms)
  found=true  begin=0x41E870  end=0x41F091  size=2081
  is_entry=true  segment=.text  is_code=true
```

Exact boundary match on an address independently established by the external
tool. The negative case behaves too:

```
POST /func_at {"rva":0x12B6B6B0}
  found=false  segment=.rdata  is_code=false
  reason="not in an executable segment"
```

That negative is the point of the whole design — see "the guard" below.

```
POST /func_stats
  .text   340,399 funcs
  .UBX0        32 funcs
  .UBX1        50 funcs
  oversize excluded: 10  (169,491,518 bytes)
```

## THE DECOY — the single most important finding

`dir_rva = 0x1AF7B320`.

The section table advertises `.pdata` at RVA `+0x14014000`. **That is a decoy
the packer left behind, and its contents are ciphertext.** Parsing it yields
structurally plausible garbage.

The real table is at PE `DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]`
(index 3). In a live process this cannot be wrong: the OS loader uses that
field for exception dispatch, and the process has not crashed.

Three independent workflow agents found this by reading the live PE header.
My own earlier note in `ANALYSIS_ENGINE_FACTS.md` had the wrong address — it
is corrected here, and `funcdb.cpp` carries the warning inline.

## CORRECTION (2026-09-19) — the oversize records were shadowing real lookups

The first version FLAGGED oversize records but left them in the lookup table.
That was a real bug, found by an audit agent and reproduced live:

```
POST /func_at {"rva":"0x14600000"}     (an address inside .UBX1)
  -> found=true  begin=0x145EA174  size=109375440
```

`by_rva()` is "last begin <= rva, then contains()". Record 8 spans
0x145EA174..0x1AE39144 — nearly the whole of .UBX1 — so EVERY query inside
that range returned the 109 MB blob instead of the function actually there.

Fixed: oversize records are now moved to a separate list (`FuncDb::oversize()`)
after the sort, so they cannot shadow ordinary lookups. They are exposed via a
new route rather than discarded:

```
POST /func_oversize {}   -> the 10 held-out records, with segment and size
```

`/func_db` now reports `lookup_table` and `oversize_held` alongside
`records_kept`, because one number cannot express "340,491 parsed, 340,481
queryable, 10 held aside".

Also fixed: `build()` cleared `m_funcs` and `m_segs` but not `m_oversize`.
Harmless in practice (parse_exception_dir clears it) but the kind of asymmetry
that bites on the next edit.

NOT yet re-verified live — the game was closed when this was written. The
build is clean; the live numbers above still describe the PREVIOUS binary.

## The oversize records

10 records exceed 1 MB; the largest claims **109,375,440 bytes** — all of
`.UBX1` as one "function". These are unwind ranges over packed/generated
regions, not procedures.

They are **kept but flagged** (`kFlagOversize`) and **excluded from coverage
aggregates**. Including them reported `.UBX1` at 102.8% coverage, which is
impossible and made the whole table untrustworthy at a glance. A consumer
wanting real functions filters them out; a consumer studying the packer wants
exactly these.

## The guard that makes a past failure impossible

Every address this API returns is accompanied by its segment name and whether
that segment is executable.

This is not decoration. Earlier work on this target produced a health finding
built on a `.data` address decoded as instructions — the bytes disassembled
into plausible code, the claim survived review, and it cost live testing time
to disprove. An API that always answers "which segment?" alongside "which
address?" surfaces that error at the moment it is made.

## Corrections to earlier notes in this repo

- `ANALYSIS_ENGINE_FACTS.md` says `.pdata` is at `+0x14014000` and computes
  340,650 entries from the section size. **Both wrong** — decoy section, and
  the real count is 340,491.
- The same file's index sizing (~70 MB) still holds and was not re-measured.

## Not yet built

Phase 2+ (xrefs, CFG, strings, vtables, decompiler) — the workflow spec was
still running when this was written. `SPEC_FROM_WORKFLOW.md` will hold it if
the run completes.
