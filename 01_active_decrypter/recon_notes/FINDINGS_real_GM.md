# Real GameManager (GameSession / Match Manager) discovered

Live capture via Bytecode against RainbowSix.exe PID 3748,
module base `0x7FF65E060000`.

## TL;DR

The current cheat's "GameManager" at `0x313091C0` is actually the
**RenderManager** — a thin object that holds the render-side ELC
container (player meshes / weapon attachment slots). It's correct
for ESP world reading but has no gameplay-state fields.

The **real GameManager** is at `0x151740` (this session) — a much
heavier object holding match GUIDs, session state, and (presumably,
based on field offsets) team rosters / score / round timer.

## Discovery method

1. Scanned `.text` for the same shape pattern that finds the
   RenderManager: `4C 8B 0D ?? ?? ?? ?? 41 83 B9 ?? ?? ?? ?? 00`
   → 21 hits across the binary.
2. Decoded the `[rip+disp32]` operand of each hit to find the
   STATIC SLOT it loads from, and the dword offset it then checks.
3. Tallied the singletons:

   | Singleton ptr   | Static slot RVA | Callers | Identity |
   |---|---|---|---|
   | `0x151740`      | `0x146F30D0`    | **12**  | **GameSession / Match Manager** ← THIS IS GM |
   | `0x18101CF0`    | `0x15885B68`    | 2       | secondary state holder |
   | `0x313091C0`    | `0x1475F308`    | 1       | RenderManager (current "GM") |
   | `0x7FF6738F5A68`| `0x15895A48`    | 1       | static config struct |
   | `0x7FF67390D458`| `0x158AD438`    | 3       | static config struct (2 disps) |
   | `0x7FF6739081D8`| `0x158A81B8`    | 1       | static config struct |
   | `0x7FF67394A060`| `0x158EA040`    | 1       | static config struct |

   The GameSession singleton wins on call-count by a wide margin —
   12 disparate functions reach into it. That call count is the
   signature of a top-level game-state object.

## Verification — fields in `0x151740`

Read live; many offsets still zero because match-end / lobby state.

```
+0x000  vtable 0x7FF671CDA190                                (rva 0x13C7A190)
+0x008  qword  0x505C   (= 20572)                            ← session/build counter?
+0x028  dword  1                                             state flag
+0x030  dword  1                                             state flag
+0x1318 byte   01                                            "session active" flag
+0x131C 36-byte ASCII string  "00000000-0000-0000-0000-000000000000"
        ← match session GUID. All-zero now (no active session);
          becomes a real UUID once you're in a match.
+0x1358 36-byte ASCII string  "00000000-0000-0000-0000-000000000000"
        ← secondary GUID (sub-session / round / lobby ID)
+0x1414 dword  1                                             session-state bool
+0x1428 dword  1                                             session-state bool
```

The `+0x1318` field is what 12 of the calling functions check
(`cmp dword [singleton+0x1318], 0`) — it's the canonical
"are we in an active session" gate. That's exactly what a
GameSession / MatchManager does.

## What this unlocks for the cheat

* **Real team assignment**: somewhere in the GameSession's
  player-records array we'll find each player's team byte.
  Stops needing the position-distance hack for `is_local`.
* **Round timer**: float seconds remaining for the current
  phase. UI overlay material.
* **Score / KD per player**: per-player stats live somewhere
  in the roster array.
* **Match GUID**: stable identifier we can show in the UI
  (e.g. "match: 1ca8-20c0").

The roster array hasn't been located yet — that's the next
hop. Should be a heap pointer somewhere in `0x151740 + 0x40 ..
0x1300` range, probably storing pointers into the same heap
zone as the `0xFC18xxxx / 0xFF17xxxx` replication-ledger
records we found in earlier sessions.

## How to find it again after a game restart

The static slot RVA `0x146F30D0` is stable across restarts (it's
in the .data section, ASLR-rebased only). Resolve at runtime:

```cpp
constexpr uint64_t GAME_SESSION_SLOT_RVA = 0x146F30D0;
uint64_t game_session = rpm<uint64_t>(module_base + GAME_SESSION_SLOT_RVA);
// Verify: vtable should be at module+0x13C7A190 (this build).
```

Alternative AOB pattern (for resilience against Ubi relinking):

```
4C 8B 0D ?? ?? ?? ?? 41 83 B9 18 13 00 00 00
```

This catches **only** the GameSession-loading sites (12 of them).
Pick any hit, decode the disp32, and that's the static slot.

## Recommended r6_offsets.h additions

```cpp
// ────────────────────────────────────────────────────────────────────
//  GAME SESSION / MATCH MANAGER — the REAL GameManager
// ────────────────────────────────────────────────────────────────────
//   Found via shape AOB: a function that loads `mov r9, [rip+disp]`
//   then `cmp dword [r9 + 0x1318], 0`. The r9 = GameSession singleton.
//
//   Verified live: holds match session GUID (ASCII format) at +0x131C
//   and an "in session" flag at +0x1318. 12 disparate callers in
//   .text reference it — the highest cluster of any singleton.
//
//   In Y9S5+post-update (current build): static slot RVA = 0x146F30D0.
//   Bake into game_session.cache the same way we bake gm.cache.
inline constexpr uint64_t GS_STATIC_RVA      = 0x146F30D0;
inline constexpr uint64_t GS_VTABLE_RVA      = 0x13C7A190;
inline constexpr uint64_t GS_SESSION_FLAG    = 0x1318;   // dword: 1 = in match
inline constexpr uint64_t GS_SESSION_GUID    = 0x131C;   // 36-byte ASCII
inline constexpr uint64_t GS_SUB_GUID        = 0x1358;   // 36-byte ASCII
```
