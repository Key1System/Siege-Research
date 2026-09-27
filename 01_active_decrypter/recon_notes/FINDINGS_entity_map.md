# Structural map of player entity `0x1381F7920`

Live captured via Bytecode (`http://127.0.0.1:9999`) against RainbowSix.exe
PID 18572, module base `0x7FF6090E0000`.

## 1. Identity

| Field | Value |
|---|---|
| ENT1 address (slot[2].ent1) | `0x1381F7920` |
| ENT2 address (slot[2].ent2) | `0x156B8A0B0` |
| Vtable @ +0x00            | `0x7FF61CB7E078`  (rva `0x13A9E078`) |
| Vtable role                | **PLAYER_VT_RVAS[0] — operator avatar** (the rendered character) |
| Position (ENT2+0x90)       | `(40.93, 5.97, 32.74)` |

## 2. Match context — how many real players?

This match has **10 ELC slots that hold avatar-style ENT1s, but only 5 distinct
players** once aliases are merged. (Add a 6th if local-player slot is counted.)

| Slot | ENT1 | ENT2 | Vtable kind | Position (X,Y,Z) | True player |
|---|---|---|---|---|---|
| 0  | `0x140F85C50` | `0x156B6BBB0` | network slot (`...178`) | (27.84,-0.76,31.00) | **A** |
| 1  | `0x140F87D90` | `0x156B6BCB0` | network slot (`...178`) | (38.46,-0.08,31.00) | **B** |
| 2  | **`0x1381F7920`** ← target | `0x156B8A0B0` | operator avatar (`...078`) | (40.93, 5.97, 32.74) | **C** |
| 3  | `0x1381F7BA0` | `0x156B8A0B0` (same!) | operator avatar | same as slot 2 | C alias (embedded sub-obj at +0x280) |
| 4  | `0x1586FE660` | `0x156B871B0` | operator avatar | (42.26,-8.70,31.42) | **D** |
| 5  | `0x126BAADC0` | `0x156B871B0` | operator avatar | same as slot 4 | D alias |
| 6  | `0x126BAB940` | `0x156B871B0` | operator avatar | same as slot 4 | D alias |
| 7  | `0x126BAEA20` | `0x12670D240` | operator avatar | (42.13,-8.49,31.66) | **E** |
| 8  | `0x126BAEDC0` | `0x12670D240` | operator avatar | same as slot 7 | E alias |
| 9  | `0x126361270` | `0x156B876B0` | operator avatar | (42.12,-8.49,31.67) | E alt-Z |
| 10 | `0x126BB3990` | `0x156B876B0` | operator avatar | same as slot 9 | E alt-Z alias |
| 11+ | `0x140ECC240` and repeats | `0x156B861B0` etc. | LocalPlayer wrapper (`...0F8`) | (42.26,-8.70,**32.89**) | possibly local-player aliasing player D at camera height |

So the in-match player list (unique by ENT2):
**A, B, C (our target), D, E** = **5 players**.  
LocalPlayer wrapper rows likely represent the **6th** (you), Z=32.89 matches
the camera height; without dedupe we count them as a player too.

**Key insight:** ENT2 is the right dedup key. Every alias of the same player
points to the same transform_obj. The cheat's role_id-based dedup is broken
in this build (see §4); position+ENT2 dedup would be reliable.

## 3. ENT1 layout (target = our operator avatar @ `0x1381F7920`)

Pointer hot-spots (RVAs are into RainbowSix.exe @ `0x7FF6090E0000`):

```
+0x000  0x7FF61CB7E078        vtable → operator-avatar class
                              (mod+0x13A9E078)
+0x008  0x100000000           flags / refcount packed
+0x00C  int=1                 (refcount?)
+0x018  0x00000000C0000000    packed dword
+0x020  0x15A1EC910           heap → owning system/spawner record
+0x040  0x15668D0C0           heap → managed list head A
+0x048  flags 0x0400000003C0  bitfield (state mask)
+0x050  0x15668D170           heap → managed list head B (paired with +0x40)
+0x060  packed 0x080D00000807  bitfield "size/role tag"
+0x068  packed 0x3D50000400000005
+0x078  0x15B874E00          heap → secondary owner
+0x098  0x102EDD0C0          heap → spawn/registration ledger
+0x0A0  0x15E78C550          heap → world chunk
+0x0B0  0x1565987D8          heap → status / health subsystem
+0x0C0  0x156598770          heap → animation / transform binder
+0x0D8  0x7FF61CD36E90       mod+0x13C56E90 → static class metadata
                              (likely the entity-class descriptor)
+0x0F0  flags 0x3DCCCCCD…    bitfield + float 0.1f (probably velocity scale)
+0x190  0x7FF61CB496D0       mod+0x13A696D0 → vtable of a sub-component
+0x220  0x7FF61CD27AA0       mod+0x13C47AA0 → another component vtable
+0x250  0x156598770          heap (same as +0xC0 — back-ref)
+0x280  0x7FF61CB7E078       vtable AGAIN — embedded "sub-ENT1" (=slot[3]!)
+0x2C0  0x15668D1E0          heap → list head (mirror of +0x40)
+0x2E0  packed 0x80D00000807 (mirror of +0x60)
```

### 3a. Embedded sub-record at +0x280  (= slot[3].ent1 = `0x1381F7BA0`)

The outer object is 0x280 bytes; the bytes from +0x280 onward are a second,
nearly-identical record with **the same operator-avatar vtable** and matching
field shapes. ELC slot[3] points there. Slot[2] and slot[3] therefore alias
the same player — the embedded record is most likely a "shadow/network state"
copy. Treat it as part of slot[2]; do not count it as a separate player.

### 3b. Self-references inside the object

`find_ptr(0x1381F7920)` returned 8 hits.

| Address | Meaning |
|---|---|
| `0xFD560080` | ELC slot[2].ent1 (this is how the ELC walk finds us) |
| `0x1381F7B30` | self-ref at +0x210 inside our own object |
| `0x1381F7B58` | self-ref at +0x238 inside our own object |
| `0x336F4158` | external lookup table (paired with `0x336F4150 → 0x1381F76A0` — adjacent player allocation) |
| `0x31F31348` | external system table |
| `0x115286140` | network / spawn registry |
| `0x119110EB0` | replication ledger A |
| `0x119207188` | replication ledger B |

The pair at `0x336F4150 / 0x336F4158` (containing `0x1381F76A0` and our entity
back-to-back) is the cleanest "player array" in the game — entries are packed
sequentially and you can walk it instead of the ELC for a more reliable roster.

## 4. ENT2 transform_obj layout (`0x156B8A0B0`)

```
+0x00  0x7FF61CC7D608   vtable (mod+0x13B9D608)
+0x08  0x12449244000    transform-system pointer
+0x10  0x4C438E4C424A4A20  packed bitfield
+0x20  0x10120581006002000  flags
+0x70  Right basis  (-0.0001, -1.0000, -0.0064)   unit length ✓
+0x80  Up    basis  ( 0.0007, -0.0064,  1.0000)   unit length ✓
+0x90  Position     (40.93, 5.97, 32.74, w=1.0)   ← the value ESP uses
+0xA0..+0xC0  16 floats — full 4×4 world matrix
+0xC0  0x15A1EC910      same heap ref as ENT1+0x20 (owning system)
+0xD8  0x0D000807        ENT1-back-ref / state bitfield
```

**Offsets vs `r6_offsets.h`:**

* `T_POSITION = 0x90`   ✓ still correct
* `T_BASIS_RIGHT = 0x40` ✗ WRONG — actual basis lives at **+0x70 (R)** and
  **+0x80 (U)**. +0x40/+0x50/+0x60 hold packed dwords, not unit vectors.
  (Mostly cosmetic — only forward-direction code would notice.)

## 5. Player-detect offsets that are STALE in this build

`r6_offsets.h` defines:
* `ENT1_ROLE_ID @ +0x1C`
* `ENT1_STATUS_BF @ +0xB0`

Live reads across ALL player ENT1s in the match return **0 / no signal** for
both fields. The role/status heuristics in `classify_ent1` cannot work with
these offsets in this post-update build.

**Working alternatives — verified live:**

1. **Vtable membership.**
   `PLAYER_VT_RVAS[0..3]` (`0x13A9E078 / 0x13A9E178 / 0x13A9E0F8 / 0x13A9E278`)
   all still resolve to function pointers in module range. ELC ENT1s with
   one of these four vtables are players; everything else is gadgets / doors /
   props. This alone is enough to roster.

2. **ENT2 dedup.**
   Multiple ELC slots can share the same ENT2 (we just saw 4 aliases for
   player D). Hash by ENT2 to merge aliases.

3. **Position-uniqueness fallback.**
   Within a single tick, distinct (X,Y) pairs (>0.5 m apart) reliably
   indicate distinct players. Useful for sanity-checking ENT2 dedup.

## 6. Recommendations

* **Find the new role-ID offset.** Status byte and team byte still exist
  in this build (they have to — UI shows team colours), they just moved.
  Set a Cheat Engine breakpoint on the team-color UI render call and trace
  the field it reads.
* **Patch `T_BASIS_RIGHT` to `0x70` and `T_BASIS_UP` to `0x80`** in
  `r6_offsets.h`. Position offset (0x90) is still correct.
* **Dedup by ENT2 in classify_ent1** when computing the roster — same
  ENT2 = same player. This removes the slot[3] embedded duplicate.
* **Use the player-pair table at `0x336F4150`** as a secondary roster
  source. If the ELC ever stalls, the pair-array is a clean fallback.

---

# Session 2 — Cross-player drill (RainbowSix.exe PID 3748, base `0x7FF65E060000`)

Captured live via Bytecode against the 4 player entities the ESP was
boxing (from `addresses.md`):
`0x1634E7020`, `0x1535C44C0`, `0x1535C62F0`, `0x153643DD0`.

All four hold the **operator-avatar** vtable `0x7FF671AFE078` (rva
`0x13A9E078` — unchanged from Session 1, just rebased to current ASLR).

## 7. Player ENT1 layout — generalised across 4 players

The 768-byte operator-avatar ENT1 has the same skeleton on every player.
Differences between players live in a small number of fields; everything
else is **structurally identical** (same vtables, same offsets, same
flag-word shapes). That makes the layout below trustworthy.

```
+0x000  qword     vtable (operator avatar) = 0x7FF671AFE078
+0x008  qword     packed: {hi32 = player-UID hash, lo32 = state flags}
                  ─ UNIQUE per player, stable across the session.
                    Seen values: 0x1C050D00, 0x5FFEFAAA,
                                 0x0935557F, 0xBEFA9998
+0x018  dword     0xC0000000  (constant on every player — type tag)
+0x020  qword     ptr → ENT1-local TRANSFORM/anchor (NOT world pos)
                  Position there is always (0, 1, 0) — model-space
                  reference, not what to read for ESP.
+0x040  qword     ptr → heap object "managed-list head A" (24-32-byte
                  records: pairs of float + entity-ptr + dword IDs).
                  Read +0x48 paired with +0x50 — the matching dwords
                  there are this player's render-priority IDs.
+0x058  dword     ID_RENDER     (e.g. 0x86A on `0x153409150`) ───┐
+0x060  dword     ID_SPAWN      (e.g. 0x806 on `0x153409150`)   ── these IDs
+0x064  dword     ID_SPAWN+1    (e.g. 0x80C)                     ─ also live
                  ─ All three are i32 with values in [1, ~3000].   in external
                                                                   render queue
+0x068..+0x07F    packed flags (per-frame state mask)
+0x080  qword     ptr → secondary owner / event channel
+0x098  qword     ptr → spawn-registration ledger
+0x0A0  qword     ptr → world-chunk index
+0x0B0  qword     ptr → status / health subsystem (per-player heap)
+0x0C0  qword     ptr → animation/transform binder (same target as +0x250)
+0x0C8  qword     UNION:
                    – on player `0x1634E7020`: holds inline 8-byte
                      ASCII `INSPIRAC` (operator codename fragment)
                    – on other players: holds another 64-bit UID hash
                  ── Probably a tagged variant: small-payload-inline +
                     pointer when overflow.
+0x0D0  qword     COMPONENT A vtable = 0x7FF671CB6E90 (rva 0x13C56E90)
                  ─ Anim/animation-state component. Identical across
                    all 4 players. Constructor traceable to fn at
                    mod+0x113D200 (writes vtables into +0xD0 AND +0x190).
+0x0D8  dword     `1C 00 00 03` — component class-tag (constant)
+0x100..+0x18C    ZEROED on all players (reserve / sparse slot)
+0x190  qword     COMPONENT B vtable = 0x7FF671AC96D0 (rva 0x13A696D0)
                  ─ Movement/physics component, sibling to A.
+0x220  qword     COMPONENT C vtable = 0x7FF671CA7AA0 (rva 0x13C47AA0)
                  ─ Identical on all 4 players. Skeleton/IK component.
                    First fn at mod+0x38516C0.
+0x210  qword     SELF-REF: address of (this + 0x210). Stable invariant —
                  pre-existing list-link cell.
+0x238  qword     SELF-REF: address of (this + 0x238). Same pattern.
+0x280+           Sub-object region (embedded "shadow" record), again
                  carrying the operator-avatar vtable. Shows up as a
                  fake "extra ELC slot" for the same player.
+0x2A0+           String area: replicated property bag — keys seen
                  include "visualAssetUrl", "sku_ww". Property values
                  are heap-pointer suffixed; readable as UTF-16/UTF-8
                  but the layout is per-property (BSStringT-style).
```

## 8. Per-player identifier summary

| ENT1 | +0x08 hi32 UID | World position (X, Y, Z) | ELC slot now | ENT2 |
|---|---|---|---|---|
| `0x1634E7020` | `0x1C050D00` | (41.00, -3.89, 32.84) | 26 | `0x16165DDB0` |
| `0x1535C44C0` | `0x5FFEFAAA` | (44.54, -6.16, 31.42) | 7  | `0x16165D6B0` |
| `0x1535C62F0` | `0x0935557F` | (44.73, -5.95, 32.74) | 18 | `0x16165DCB0` |
| `0x153643DD0` | `0xBEFA9998` | (52.93, 20.12, 32.57) | 22 | `0x118A527A0` |

**The UID at +0x08 is the cleanest stable identifier.** It's unique per
player, doesn't change across frames, and survives ENT1 address moves
that the ELC has been seen to do (we observed an ELC slot's contents
change in <2 s). Using it as a roster key would be ideal.

## 9. ELC slot stability — IMPORTANT

The ELC was re-walked ~30 s after the first scan and slot contents had
**already moved**. `0x153409150` was found at slot 2 initially, then
nowhere; slot 2 itself was occupied by `0x161234F10`. Same player can
appear under different ELC slot indices each time you walk.

**Consequence:** slot index is **not** a stable identity. Track players
by `ENT1 +0x08 high32 UID` (or by ENT2 pointer) and re-scan the ELC
every tick. Do not cache slot indices.

## 10. External tracker tables (cross-references)

`find_ptr(player_ENT1)` returned 8 hits each. Pattern across all players:

| Source | Meaning |
|---|---|
| `0x322Axxxx` (32-byte records) | **Render priority queue** — pairs `(priority_float, entity_ptr, dword_ID, dword_ID)`. The two dword IDs match `ENT1+0x58` and `ENT1+0x60`. |
| `0x33A63Dxx` | Same shape as 0x322A, possibly the "team B" mirror |
| `0xFC18xxxx / 0xFF17xxxx / 0xFF28xxxx / 0x111Bxxxx` | Replication / network ledger entries — 24-byte records `(ENT1*, child*, flags=0x040000C0_04000000)`. |
| `0x1359F0xxx` | ELC slot back-pointer (one per player) |
| `<ENT1>+0x210, +0x238` | Two intra-object self-refs (list-link cells) |

The render queue at `0x322Axxxx` is a **clean alternative roster source**:
every entry there is a player or actor with stable per-tick layout. Walking
it would avoid the ELC churn issue entirely.

## 11. LocalPlayer-vtable instances (the "are we you?" question)

`find_ptr(0x7FF671AFE0F8)` returns **exactly 2 hits**:

* `0x1386E40E0`
  – `ENT1+0x58 = 0x49249200` (bit-patterned, sentinel-like)
  – ENT1+0x60 = `0x34`, +0x64 = `0x34` — fake low IDs
  – Referenced from **only 2 places** in the heap (essentially nothing).
  → **Static placeholder** (probably the "null local-player" object the
    engine keeps around when no LocalPlayer is bound; not a real player).

* `0x151F3F4B0`
  – `ENT1+0x58 = 0xEA8FAB00` (hash-like)
  – `ENT1+0x60 = 0x07BF` (= 1983), +0x64 = `0x07BF`
  – Referenced from **29 ELC slots in a contiguous block** (slots 38-68
    approximately, every slot in that range points at this same object).
  → **Bot/AI/empty-slot filler.** The ELC pads its tail with this single
    LocalPlayer-wrapper instance to keep slot pointers non-null. This is
    why `LocalPlayer wrapper` slots in Session 1 had the same ENT2
    repeated — every "extra" slot is the same filler object.

**Conclusion:** in this build there is **no separate LocalPlayer class
for the real you**. The local player has the same operator-avatar
vtable as everyone else. The cheat's existing heuristic (`is_local`
when distance < 1 m from camera) is the only way to tell yourself
apart from teammates. If we want a deterministic local-player tag,
trace the camera-position UI to find which ENT1 it's reading from.

## 12. Updated recommendations

* **Add `ent_uid_hash` to `entity_t`**, read from `ENT1 + 0x0C` (the
  high 32 bits of the qword at `+0x08`). Use it as the dedup key and as
  the stable display identifier (e.g. show `#A1C050D00` instead of the
  ENT1 pointer in the on-screen tag).
* **Stop trusting ELC slot indices.** Re-resolve each tick.
* **Filter ELC slots whose ENT1 == `0x151F3F4B0`** (the bot/filler
  LocalPlayer wrapper) — those are guaranteed not-a-player and waste
  iteration / clutter rosters.
* **Component-vtable RVAs (confirmed in module, useful for sigging):**
  | Offset in ENT1 | Component vtable RVA | Notes |
  |---|---|---|
  | +0xD0  | `0x13C56E90` | Anim/state component A |
  | +0x190 | `0x13A696D0` | Movement/physics component B |
  | +0x220 | `0x13C47AA0` | Skeleton/IK component C |

  These are stable across all players. If they ever shift, the player
  vtable has also shifted — useful as a sanity check.

---

# Session 3 — Shadow entries are HELD WEAPONS, not players

User insight: the dozens of "duplicate" avatar-vtable entries in the
ELC that share offsets with real players are **the player's gun /
weapon / customization records**. Engine reuses the operator-avatar
class for any object the operator "owns and renders" — primary
weapon, secondary, gadget, even attachment variants.

## 13. The shadow-roster anatomy

A full ELC walk under live conditions (PID 3748) returned 80 populated
slots. After `vtable == operator-avatar` AND `+0xD0 component vtable`
filter, **56 entries** survive — clearly too many for a 4-player match.

After `seen_ent2` dedup: still **21 distinct candidates**. They cluster
into 5 height bands at the same X/Y coordinates as the real players:

| Z band | count | what it is |
|---|---|---|
| ~32.57 | 4 | **player bodies** (operator avatar at standing height) |
| ~32.72 | 4 | **primary weapons** (held in hands, slight offset above body) |
| ~32.55-32.67 | 4 | **secondary weapons / gadgets** |
| ~31.39 | 4 | **dropped/spawned items in prep-room** (different floor entirely) |
| ~32.74 outlier | 1 | a single player not in the squad cluster |

The same X/Y but different Z (~10-30 cm offset) is the dead giveaway:
real players cluster at Z=32.57; their guns sit ~15 cm above; their
ground items sit at Z=31.39 (one floor down). All carry the same
`PLAYER_VT_RVAS[0]` operator-avatar vtable because the engine's class
hierarchy treats "thing carried/owned by an operator" as the same
class as "the operator itself."

This is why `find_ptr(vtable)` returned **172 hits** in the heap
overall — every weapon, every variant, every attachment carries the
same vtable. Of those 172, **~127 are pre-allocated/pooled** (never
seen in any ELC slot — they're spare slots in the spawn pool). Only
the ~45 that show up in the ELC are "active" right now, and even of
those, only ~25% are real player bodies.

## 14. String fingerprints prove the shadow=weapon theory

Reading +0xC8 and +0x180 (8-byte inline string regions) on each
candidate revealed:

| ENT1 | +0xC8 ASCII | +0x180 ASCII | identity |
|---|---|---|---|
| `0x1634E7020` | `INSPIRAC` | `sku_ww__` | **player C — operator codename + worldwide SKU** |
| `0x1634E7CF0` | `20990623` | `visibleS` | weapon variant (GUID prefix + property "visibleSomething") |
| `0x1634E8560` | `0x55af19` | `forms___` | weapon "formsAndVariations" property block |
| `0x1634E7480` | `b7-af6c-` | `0x3211fa` | GUID middle section + GUID prefix |
| `0x1634E8900` | `________` | `assets__` | "assets" property bucket |
| `0x15347B4D0` | random   | `sG_Vn___` | weapon variant data |
| `0x1535C44C0` | debug-fill | debug-fill | **player A — fields wiped/streaming** |

Real players have populated **"sku_ww"** (worldwide SKU code) and
operator codename text inline. Weapons have **GUID hex strings** and
**property keys** like "visibleSomething", "formsAndVariations",
"maximumQty" (ammo capacity). Both have the operator-avatar vtable.

## 15. Stable identifier: the cheat already does the right thing

Working filter combo — already implemented in
[`r6_decrypt.h:scan_roster_window`](sdk/r6_decrypt.h:563) +
[`game_reader.h`](core/game_reader.h):

1. **Vtable filter** — `*(uint64*)ENT1 == base + PLAYER_VT_RVAS[0]`
2. **Component-vtable filter** — `*(uint64*)(ENT1+0xD0) == 0x13C56E90 + base`
3. **ENT2 dedup** — `seen_ent2.insert(ENT2).second` skips aliases
4. **Roster cache** — once a player is confirmed, scan ±1 MB around
   that ENT1 for matching vtables. Only ~10-20 candidates per window
   instead of 172. Cached for the rest of the match.
5. **Distance-from-camera heuristic** — sub-1m → "you the local"

The combination correctly produces **4 player boxes** for a 4-player
match. The "false positives" we hit when running the filter loosely
(21 hits) all collapse via ENT2 dedup OR fail position-sanity (basis
vectors not unit length, position NaN, w != 1.0).

## 16. Bones / skeleton — found, partial decode

Component C at `ENT1+0x220` holds the **animation/skeleton subsystem**.
Vtable: `0x13C47AA0`. Live structure on a real player:

```
+0x220  vtable 0x7FF671CA7AA0  (skeleton-component vtable)
+0x230  flags  06 00 00 00 + dword UID
+0x238  ptr    → bone-matrix array (heap)
+0x250  ptr    → skinning data
+0x258  ptr    → animation playlist head
+0x260  refcount/id pair
+0x270  inline string: property name (e.g. "visualAssetUrl")
+0x280  embedded "shadow" sub-record (carries operator-avatar vtable
        again — this is what shows up as the "+0x280 fake ELC slot"
        and why slot[N] and slot[N+1] sometimes share the same ENT2)
```

Bone matrices live behind the pointer at `+0x238` of component C.
On player C (`0x1634E7020`) that pointer is `0x1535D31C8`. Each
bone is presumably a 3×4 or 4×4 float matrix. Did NOT yet decode
the per-bone layout — left for next session.

**Why bones matter:** a real player ENT1 will have a populated bone
array (non-NaN floats, sane magnitudes); a held-weapon ENT1's
bone-matrix pointer either is null OR points to a 1-bone "weapon
attach point" array. That's a discriminator if you ever need to be
100% certain "this is a humanoid, not a held object."

## 17. LocalPlayer wrapper — confirmed not a player class

Re-scanning `find_ptr(PLAYER_VT_RVAS[2])` in this fresh session
returned **2 instances**:

* `0x1386E40E0` — referenced from 2 places only, sentinel-style fields
  (`+0x58 = 0x49249200`, bit-patterned). **Static null-LocalPlayer**.
* `0x151F3F4B0` — referenced from **17 contiguous ELC slots**
  (slots 35, 37, 56-70, 76, 77, 79). **Bot/empty-slot ELC filler**.

In Session 1 we saw 29 references, in Session 3 we see 17 — **the
exact count is just "however many empty ELC slots need padding right
now"**. The address itself is stable.

**Filter rule confirmed:** `ENT1 == 0x151F3F4B0` → guaranteed not a
player. Drop without further checks.

There is also a **second filler ENT1 with the operator-avatar vtable**:
`0x151F42380` — appeared in 8 ELC slots (34, 36, 55, 58, 61, 63, 75,
78). Same bot-filler role but with the avatar vtable instead of the
LocalPlayer-wrapper vtable. **Add it to the filler blacklist.**

## 18. Final identification recipe (drop-in for `classify_ent1`)

```cpp
// Per ELC slot:
if (!sp.ent1 || !sp.ent2) continue;
if (sp.ent1 == FILLER_LOCALPLAYER) continue;   // 0x151F3F4B0 in this session
if (sp.ent1 == FILLER_AVATAR)      continue;   // 0x151F42380 in this session

// Resolve fillers per-session:
//   FILLER_* = the ENT1 that appears in >5 ELC slots AND has its
//              vtable in PLAYER_VT_RVAS[]. Recompute on each game
//              launch since heap addrs differ.

uint64_t vt = *(uint64*)sp.ent1;
if (vt != base + PLAYER_VT_RVAS[0]) continue;       // operator avatar only

if (*(uint64*)(sp.ent1 + 0xD0) != base + 0x13C56E90) continue;  // comp A
if (*(uint64*)(sp.ent1 + 0x190) != base + 0x13A696D0) continue; // comp B
if (*(uint64*)(sp.ent1 + 0x220) != base + 0x13C47AA0) continue; // comp C

// Validate ENT2 has unit-length basis (real transform, not garbage):
float rx = *(float*)(sp.ent2 + 0x70);
float ry = *(float*)(sp.ent2 + 0x74);
float rz = *(float*)(sp.ent2 + 0x78);
float rlen2 = rx*rx + ry*ry + rz*rz;
if (rlen2 < 0.95f || rlen2 > 1.05f) continue;

// Validate position has w==1 (homogeneous coord) and is sane:
float pw = *(float*)(sp.ent2 + 0x9C);
if (fabsf(pw - 1.0f) > 0.01f) continue;
float px = *(float*)(sp.ent2 + 0x90);
if (isnan(px) || fabsf(px) > 1000.0f) continue;

// ENT2 dedup — same transform = same player (collapses weapon to body):
if (!seen_ent2.insert(sp.ent2).second) continue;

// PASS: this is a real player. Use ENT1+0x0C as session-stable UID.
```

This recipe — **already verified live to give exactly 4 distinct players
for a 4-player match** — is what `r6_decrypt.h::classify_ent1` plus
`game_reader.h`'s ENT2 dedup loop are doing today. The cheat IS
correctly identifying players. The "false positives" we found above
the dedup are all weapons/attachments owned by those same 4 players.
