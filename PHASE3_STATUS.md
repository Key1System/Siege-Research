# Phase 3 — the string index — BUILT, NOT YET VERIFIED LIVE

Date: 2026-09-19. Siege was not running. **Nothing below is measured.**

## What exists

| file | role |
|---|---|
| `src/analysis/strings.h` | `str_t`, `str_enc`, `classify()`, `StrDb`, `sdb()` |
| `src/analysis/strings.cpp` | chunked scan, ASCII + UTF-16LE, lookup and search |
| `src/analysis/routes_strings.inc` | `/str_build` `/str_find` `/str_at` `/str_xref` `/str_stats` |

Wired into `server.cpp` and `CMakeLists.txt`. **Builds clean**
(`BytecodeInternal.dll`, 2026-09-19 12:45).

## Why this phase exists

Phases 1 and 2 are anonymous. `sub_41E870 calls sub_9A2C10` says nothing about
what either does.

Strings are the only labels a stripped binary keeps — assert messages, log
formats, class names, config keys. Each is the developer's own description of
the code that references it. Joined against the xref index:

```
/str_find  "PlayerController::OnSpawn"   -> rva
/str_xref  that rva                      -> the function that loads it
```

and an anonymous function acquires a name. That join is `/str_xref`, and it is
the point of the phase.

## What counts as a string

Not "a run of printable bytes" — that matches vast amounts of binary data, and
an index full of `\x20\x20H@\x01` hides the real strings in noise. Three
filters, each killing a specific false positive:

| filter | default | kills |
|---|---|---|
| minimum length | 5 chars | short printable runs inside pointer tables |
| **NUL terminator** (ASCII) | required | runs that end because the next byte is `0x80` |
| plausibility score | >= 25 | `@@@@@@@@`, `....::::`, punctuation soup |

`classify()` scores 0–100 on letter fraction, with partial credit for digits
and identifier punctuation (`_ : . / %`) so `../../src/x.cpp` and `%s: %d/%d`
survive — format strings are exactly what we most want to keep.

**The score is stored, not applied as a hard filter at scan time.** A caller
hunting a known class name wants everything; a caller browsing wants only the
obvious. Collapsing that to accept/reject at scan time would force a rescan of
hundreds of MB to change one threshold.

## Where it looks, and why

**Data sections only.** Scanning `.text` finds the byte patterns of
instructions that happen to be printable — a large and purely false crop that
would bury the real results. Code *references* its strings; it does not
contain them.

Chunked at 1 MB with a 4 KB overlap so a literal straddling a chunk boundary
is not split into two fragments that both fail the length test. An unreadable
chunk is skipped rather than abandoning the whole section — one hole would
otherwise lose every string after it.

UTF-16 is detected as printable ASCII interleaved with zero bytes, on
2-byte-aligned offsets only (odd starts would produce a shifted duplicate of
every string found). **This misses non-Latin text.** That is an accepted,
stated limitation rather than an unknown one, and `/str_stats` says so in its
`completeness_note`.

## Safety

Same rules as phase 2: time-sliced (`budget_ms`, clamped [50, 30000]),
resumable, and **a partial index is never published** — it would answer "no
such string" for anything unscanned, which reads as a finding rather than an
incomplete scan.

## Expected shape — TO BE CONFIRMED

| quantity | expectation |
|---|---|
| strings | 100k–500k |
| index memory | 1–6 MB (`12 B` each — small; the text stays in the host) |
| full scan | 1–5 s over ~150 MB of data sections |

`/str_stats` returns a score distribution so the threshold can be judged from
data. **If nearly everything sits in the `0_24` band, the filter is admitting
noise and `min_score` should go up before any conclusion is drawn.**

## First live checks

1. `/str_build {}`, repeating with `{"resume":true}` until `complete:true`.
2. `/str_stats` — check the score distribution, then `total`.
3. `/str_find {"q":"Reflex"}` — a known-present subsystem name. Zero hits
   means the scan is broken, not that the string is absent.
4. `/str_xref {"q":"Player"}` — the actual objective: named functions.

Check 3 is the honest test; 1 and 2 only prove the scan ran.
