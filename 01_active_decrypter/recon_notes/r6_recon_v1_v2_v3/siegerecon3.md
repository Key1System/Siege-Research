# R6 Siege RE — recon v3 (clean / focused)

> Distilled from `siegerecon2.md` (4400+ lines) — this file contains
> ONLY verified, actionable findings. No dead ends, no exploratory
> failures, no retractions-of-retractions. For full audit trail, see
> the earlier reports.

---

## Engine fingerprint

* Binary: `RainbowSix.exe` (PE x64)
* PDB / engine name: **`scimitar_engine_win64_2022_flto_dx12`** (LTO-built)
* Engine: **Scimitar** (Ubisoft Montreal's Anvil fork)
* Physics: **Havok 2024.2.0** (hknp* + hk* classes)
* Protection: **VMProtect** (`.UBX0` 3 MB + `.UBX1` 129 MB) + MBA wrappers
* Player class name: **`Pawn`** (per `PawnIsProne`, `PawnAimBaseRotation`, etc.)

---

## BaseEntity layout (VERIFIED, multi-source)

| Offset | Type | Field | Verification |
|---|---|---|---|
| `+0x00` | qword | vtable ptr (Ubisoft-stripped, no MSVC RTTI) | live + static |
| `+0x18` | qword | parent/owner ptr | decomp `entity[+0x18][+0x80] = child list` |
| `+0x20` | dword | flags (low 2 bits = active/visible-ish) | decomp |
| `+0x50` | vec4 float | **world position** `{x,y,z,w=1.0}` | live read at user's entity (matched broadphase entry) |
| `+0xD0` | qword | **ComponentList ptr** | **5-way verified** |
| `+0xF8` | qword | **Anvil handle** `{gen:32, flags:2, slot:30}` | §42 disasm |
| `+0x110/+0x140/+0x170` | inline | sub-component vtables (embedded multi-inherit objects) | §39.3 dissect |
| `+0x1E0..+0x22D` | byte table | **component-type → ComponentList slot** lookup table (~78 entries, 0xFF = absent) | scan-confirmed, 46 unique offsets used in 8 MB sample |

### Critical slot bytes within +0x1E0..+0x22D

| Slot offset | Times accessed (8 MB sample) | Notes |
|---|---|---|
| `+0x1E3` | **71** | Most-accessed. Paired with `+0x1FB` (same API). State or script component. |
| `+0x1FB` | **35** | Paired with `+0x1E3`. |
| `+0x221` | 22 | popular |
| `+0x225` | 10 | popular |
| `+0x1E8` | ? | likely DamageComponent (per §21 static) |
| `+0x1F4` | ? | accessed by Anvil handle-resolver (§42) |
| `+0x22C` | ? | accessed by destruction path (§47) |

The two most-accessed slot bytes (`+0x1E3` and `+0x1FB`) hold components with the **same generic interface** — calls like `op(comp, value); finalize(comp)`. Strongly suggests `StateComponent` (server/client pair) or `ScriptComponent` (primary/proxy).

### ComponentList structure

* Flat array of qword pointers (one ptr per slot)
* `0xFFFFFFFF` sentinel at `+0xE8` of ComponentList
* count/capacity dword at `+0xEC`
* Lookup: `entity[+0xD0][slot_byte * 8]` → component pointer

---

## Anvil handle layout (VERIFIED via §42 handle-resolver disasm)

```
bits[63..32]  generation (full 32 bits)
bits[31..30]  flag bits (preserved across refresh via mask 0xC0000000)
bits[29..0]   slot index (30 bits → 1B max entities)
```

Stored at `entity[+0xF8]`. Bit 31 likely strong-ref flag.

---

## Anvil class registry

* **Root global**: `off_7FF6D91D3E80` (referenced **4189× in 32 MB sample** — engine-wide backbone)
* Slot-table at `+880` (= 110 qwords)
* Per-slot vtable array at `+888` (= 111 qwords)
* 7-bit class ID (max 127 classes per page)

---

## Anvil class hash + `is_a()` predicate pattern

Each class has a precomputed 32-bit hash + a per-class lazy-init helper that publishes `{hash, name_ptr}` to a global slot. Examples:

| Class | Hash |
|---|---|
| `R6Facility` | `0x8F926396` (-1890734378) |
| `Facility` (base) | `0xE93FAE24` (-382732572) |
| `R6DestructionManagerTerminalHandler` | `0x97891C7C` (-1754939908) |
| `R6GameFlow` | `0x3BD1ABD5` (1003964693) |
| `R6GameFlowServiceGroupContext` | `0xBF4E2386` (-1085587130) |
| `NotificationExternalApplicationSnapped` | `0x2858FE07` (677353735) |

The `is_a()` test walks the class chain: `*type_id == R6Facility_hash || *type_id == Facility_hash`.

---

## Service registry (unified system for services + components)

* **Registrar**: `sub_7FF6C9B7DEE0(root, parent_id, name_ptr, name_len)` — returns int ID
* **Root**: `unk_7FF6D9047E00`
* **8587 xrefs** to the registrar across the binary
* Both R6Services AND ECS components (like `RigidBodyComponent`) use this same registrar
* Cached IDs stored in per-class globals (e.g. `dword_7FF6D93DF50C` for RigidBodyComponent)
* HAS-COMPONENT check: `sub_7FF6CA7E4E30(table_ptr, type_id)` against `qword_7FF6D93E1B60`

### Service tree

```
NetworkService
  ├─ NetEngineParams.{EmulatorEnable, LogEnable, NetworkThreadType}
  ├─ NetLog.{LogAssertEnable, LogErrorEnable, LogResultEnable}
  └─ NetQos.{PingEnable, PingPeriodInMs}

OnlineModule
  ├─ Global
  ├─ LowLevel
  ├─ User
  └─ Session.Game.Host

System
  └─ SytemToServerTimeDelta   (sic — "Sytem")
```

---

## TLS-keyed state gates

| TLS offset | Field | Used for |
|---|---|---|
| `+0x14` | thread-init flag | Pre-gate on every Anvil-touched function |
| `+0xCCC` (= 3276) | **in-match flag** (`==2` means in match) | **5-way verified** gate on physics, handle-resolve, network code |
| `+0x4B80` (= 19328) | profiler/logger ptr | Per-frame stage profiling (§58) |

Access pattern:
```c
TLS_slot = TLS[TlsIndex];
if (TLS_slot[+0xCCC] == 2) { ... in-match logic ... }
```

---

## Havok physics — what's actually in Siege

### hknpWorld (size **4432 bytes**)
* Multi-inherit (3 vtables: primary + 2 sub-interfaces)
* Siege overrides primary vtable (~30 vfuncs) + vtbl3 (23 vfuncs)
* vtbl2 is passthrough (Havok defaults)

### Key hknpWorld offsets

| Offset | Field |
|---|---|
| `+0xB78` | simulation engine (ST 1632 B or MT 1776 B) |
| `+0xE18` | per-frame callback list |
| `+0x10B0` | hknpCharacterProxyManager (40 B, lazy-init) |
| `+0x1130` | back-ref to Physics Manager |
| `+0x1140` | flag/state |

### Physics class sizes (top 20)

| Size | Class |
|---|---|
| 22944 | hknpGlobals |
| 14784 | hknpDefaultModifierSet |
| 14176 | hknpCollisionQueryDispatcher (= 0x3760) |
| 7904  | hknpProcessNarrowPhasePairsTask |
| 7424  | hknpParticlesCollider |
| 6296  | hknpModifierManager |
| 4432  | hknpWorld |
| 3480  | hkcdPlanarGeometryPolygonCollection |
| 3360  | hknpBodyQualityLibrary |
| 2928  | hknpSimdTreeBroadPhaseInternal |
| 2496  | MT19937_buffer |
| 2096  | hknpCollisionCacheManager |
| 1776  | hknpMultithreadedSimulation |
| 1632  | hknpSimulationContext |
| 1360  | hknpCollisionDispatcher |
| 1120  | hknpSimdTreeBroadPhase |
| 464   | hknpRagdollConstraintData |
| 432   | hknpWheelConstraintData (drone) |
| 240   | hknpHingeConstraintData |
| 184   | hknpCompoundShape |

### hknpCharacterRigidBody = **160 bytes**
* Allocated via `qword_7FF6D91348A8`, tagged via `off_7FF6D91348B8(p, "hknpCharacterRigidBody")`
* Siege-overridden vtable at `0x7FF6D8517BE0`
* Created by `sub_7FF6CA8BC540` (1.9 KB) — uses Anvil packed RW spinlock

### Siege-specific physics classes

| Class | Role |
|---|---|
| `R6CharacterContactFilter` | character collision filter (team check) |
| `R6DefuserMassModifier` | defuser custom physics mass |
| `R6DestructionManagerTerminalHandler` | destruction event endpoint |
| `R6Facility` | per-map physics facility |
| `RollingSlidingSoundModifier` | physics→audio bridge |
| `RigidBodyComponent` | per-world physics manager (registered as service) |

### Destructible mesh pipeline

`hknpBreakableCompoundShape` + `hknpBreakableConstraintData` + `hknpBreakableCompoundShapeKeyMask` — Havok-side. `sub_7FF6CB163510` is the Siege-side handler with material-range filtering (`word_7FF6D9C2D0C0`/`word_7FF6D9C2D0C2`).

---

## Per-frame world update stages

`sub_7FF6C5F1B900` is the **stage advancer**. Each frame cycles through:

| Stage byte | Just-finished stage | Next |
|---|---|---|
| `0` | PrePhysics | Physics |
| `1` | Physics | PostPhysics |
| `2` | PostPhysics | (frame end) |
| `3` | between-frames | PrePhysics |

Verified via the `.rdata` profiling marker strings:
* `WorldUpdate_ctx`
* `WorldUpdate_PrePhysics_ctx`
* `WorldUpdate_Physics_ctx`
* `WorldUpdate_PostPhysics_ctx`

Stage tracker: `world_obj[+416]->[+408]`, current stage byte at `+40` within tracker, end timestamp via `__rdtsc()` at `+80`.

---

## Health (HONEST STATE)

### Where HP is NOT (retracted)

* `sub_7FF6D30CA6D0` is **`scimitar::R6TrackingUtil::ConvertToJson`** — gameserver telemetry JSON serializer, NOT a player accessor. The `HEALTH:%.2f` log + `[r13+0xAB8]` were reading from a **6784-byte tracking record blob**, not a player struct.
* `DamageComponent[+0x150]` is NOT a state enum (live byte was 0xC0000000 = float -2.0).
* `DamageComponent[+0x15C]` is NOT HP (it's a seconds timer).
* `currentHealth` / `CharHealth` strings have **0 lea xrefs** — dead tooling metadata.

### What we DO know

* DamageComponent IS attached at a slot in BaseEntity's ComponentList (slot byte at one of the slot-table offsets, likely +0x1E8).
* Mira's gear shellhealth at `gear_struct[+0x1C]` = u32.
* HP is per-Pawn, accessed via the property hash system, NOT a static fixed offset.

### Best next probes for finding actual HP

1. Hunt the 28 KB caller `sub_7FF6D3B95010` of the tracking-record builder — its upstream copies HP from the real source into the snapshot.
2. Look at DamageComponent vtable for functions returning a float — that's likely `getHealth()`.
3. Live: walk a player's ComponentList in-match and dissect each component for HP-shaped floats (0..200 range).

---

## DamageComponent vtable structure (NEW — extended from §80 work)

* Vtable address: **`0x7FF6D88C66D0`** (translated from old IDA imagebase)
* ~40 vfuncs, mostly stubs (`nullsub_1` at slot 8,10-11,14,17,19-21,24-27,32,34-39)
* 3-byte return-zero stub at slot 0,5,7,12-13,15,22,29-30,33 (`sub_7FF6C5883FD0`)
* **Real vfuncs**:
  * `vtbl[2]` = clone/copy (548 bytes) — `sub_7FF6C7C05700`
  * `vtbl[3]` = destructor (157 bytes) — `sub_7FF6C8013290`
  * `vtbl[4]` = "register as ManagedObject" (99 bytes) — `sub_7FF6CA7C6150`
  * `vtbl[6]` = (683 bytes)
  * `vtbl[9]` = forwards to sub-object at `this[+0x80]` (38 bytes)
  * `vtbl[18]` = **MAIN HANDLER** (5013 bytes) — likely OnDamage / Process
  * `vtbl[23]` = (1872 bytes)
  * `vtbl[28]` = (1902 bytes)
  * `vtbl[31]` = (4654 bytes) — also big, likely secondary handler

### DamageComponent layout (extended)

| Offset | Field |
|---|---|
| `+0x00` | vtable ptr (`0x7FF6D88C66D0`) |
| `+0x28` | vtable2 (multi-inherit) |
| `+0x70` | slot ID stamp (back-ref to BaseEntity ComponentList slot byte) |
| `+0x80` | sub-object with its OWN vtable (HealthState? embedded sub-component) |
| `+0x7C8` (1992) | int32 array data ptr |
| `+0x7D0` (2000) | int32 array count + flags packed |
| `+0xA20` (2592) | byte flag (copied during clone) |
| ≥ 2593 bytes total |

### `ManagedObject` system

* Hash: **`0xBB97DF7D`** (`3147194493` = `-1147772547` signed)
* String used in `sub_7FF6CA7C80F0(this, "ManagedObject", 0, 0xBB97DF7D, ptr)` registration
* Global hash table at `qword_7FF6D93DF5F0` indexes all ManagedObjects
* Cleanup via `sub_7FF6CA80CF10` (uses 0x40000000 + 0xFFFFF flag mask on `this[+8]`)

## BaseEntity paired-component finding

`sub_7FF6C7139100(entity, mode_value)` operates on BOTH slot `+0x1FB`
and slot `+0x1E3` components with **identical interface**:
* If `mode_value[0]`: call `sub_7FF6C86E1F30(comp, mode_value[1])`
* Else: call `sub_7FF6C8696C80(comp, mode_value[1])`
* Always followed by `sub_7FF6C875AFE0(comp)` (finalize)

The two components have the SAME API — strongly suggests they're
**a state-machine pair** (current/target, server/client predicted, or
primary/secondary script).

## Embedded sub-vtables on BaseEntity (NOT health-related)

The user's entity dump showed sub-vtables at `+0x118`, `+0x140`,
`+0x170`. Investigation reveals these are **intrusive linked-list
node helpers** — destructor pattern: restore vtable, unlink from
prev/next, free via Anvil registry. So BaseEntity has 3 inline
list-node sub-objects (probably for: render list, physics list,
network list).

NOT health, NOT player-state. Just bookkeeping.

## HP float-constant scan (negative result)

Searched `.rdata` + `.data` for IEEE-float bytes of common
R6 max-HP values:
* 100.0f: 56 in .rdata, 19 in .data (too generic — used everywhere)
* 110.0f: **0** occurrences
* 120.0f: 6 / 4
* 125.0f: **0** occurrences
* 200.0f: 7 / 2

Confirms operator-specific HP values are loaded from **DATA FILES**
(operator config), not hardcoded. Bypasses static-constant search.

---

## ★ The 3-deref chain DamageComponent → health (PARTIALLY MAPPED)

User confirmed: from BaseEntity, the path is `BaseEntity → ComponentList → ClassCompare for DmgComponent → DamageComponent → health` with the last segment being a "chain of 3" derefs.

### The chain (3 vtables identified, last deref still unknown)

```
Level 0: BaseEntity
   ↓ entity[+0xD0]
ComponentList
   ↓ walk + ClassCompare to find DmgComponent
DamageComponent  (vtable 0x7FF6D88C66D0)  — size ≥ 2593 B
   ↓ this[+0x80]
HealthSubObject  (vtable 0x7FF6D87E24B0)  — embedded sub-object
   ↓ this[+0x10]
Level3Object  (vtable 0x7FF6D8821280)  — sized at least 234 B
   ↓ this[+0x30] (refcounted handle) → resource
???  (the actual HP-bearing leaf)
```

### How each level was identified

* **DamageComponent vtable** (`0x7FF6D88C66D0`) — direct from live read of user's entity at `0x13B6324E0` ComponentList slot (§39).
* **HealthSubObject vtable** (`0x7FF6D87E24B0`) — found in DamageComponent destructor `sub_7FF6C7C1B220`:
  ```c
  *(_QWORD *)(a1 + 128) = &unk_7FF6D87E24B0;   // restore HealthSubObject vtbl at this+0x80
  ```
  Also confirmed via vtbl[9] forwarding: `((this+0x80)->vtbl[9])((this+0x80))`.

* **Level3Object vtable** (`0x7FF6D8821280`) — found in HealthSubObject destructor `sub_7FF6C7F321A0` which calls `sub_7FF6C7B65BD0(a1 + 16)` (= operates on Level3Object at HealthSubObject+0x10). Level3Object's own destructor sets `*(_QWORD *)a1 = &unk_7FF6D8821280;`.

### Level3Object findings

| Vtable slot | Function | Size | Notes |
|---|---|---|---|
| 2 | clone (`sub_7FF6C7F7EC90`) | 201 B | object has field at +233 (alive byte?) |
| 3 | destructor (`sub_7FF6C7DEADF0`) | 147 B | sub_7FF6C7B65BD0(this) cleanup |
| 4 | ManagedObject registration (`sub_7FF6CA7C6150`) | 99 B | |
| 6 | deserialize byte (`sub_7FF6C7FAEA90`) | 172 B | reads byte → this[+233] |
| 20 | clone-2 (`sub_7FF6C63E7960`) | 204 B | clones sub-object at +0x30 |
| 21 | derived destructor (`sub_7FF6C63A08C0`) | 273 B | restores vtable `0x7FF6D8821310` (derived class!) |
| 24 | deserialize handle (`sub_7FF6C63B07A0`) | 40 B | writes refcounted handle to this[+0x30] |

### Level3Object layout (partial)

| Offset | Field |
|---|---|
| `+0x00` | vtable ptr |
| `+0x08` | secondary vtable (`0x7FF6D86288B8` from derived dtor) |
| `+0x30` | refcounted handle (qword) — points to ANOTHER resource |
| `+0xE9` (233) | byte (alive flag?) |

### Derived class: vtable `0x7FF6D8821310` (offset +0x90 from Level3Object's `0x7FF6D8821280`)

The derived class adds 144 bytes of vfuncs (0x90 / 8 = 18 more vfuncs). It restores its own vtable AND sets `[+8] = &unk_7FF6D86288B8`. So there's a CLASS HIERARCHY:
* Base: Level3Object (vtable `0x7FF6D8821280`)
* Derived: Level3ObjectDerived (vtable `0x7FF6D8821310`)

### Last-deref question (still open)

The "chain of 3" is now resolved to 3 vtables. HP must be at one of:
* **Level3Object[+0x30]** — a refcounted handle to a resource; the resource contains HP
* **Level3Object[some float offset]** — direct float field
* **The derived class's added fields** — beyond the base Level3Object layout

Need either a live instance to dissect at runtime, OR a function that's clearly `getHealth() → float` on Level3Object's vtable. None of the small vfuncs return float directly via xmm0.

### Helper function inventory (from the chain)

| Function | Role |
|---|---|
| `sub_7FF6C7C1B220` | DamageComponent destructor |
| `sub_7FF6C7F321A0` | HealthSubObject destructor |
| `sub_7FF6C7B65BD0` | Level3Object destructor |
| `sub_7FF6C7B0EE30` | HealthSubObject.vtbl[9] (cleanup all entries in pool) |
| `sub_7FF6C8696C80` | Generic component op (used by sub_7FF6CB18FA10) |
| `sub_7FF6C86E1F30` | Generic component op (path A in sub_7FF6C7139100) |
| `sub_7FF6C875AFE0` | Component finalize (MBA-wrapped) |
| `sub_7FF6CA80CF10` | ManagedObject lifecycle cleanup |
| `sub_7FF6CA7C80F0` | ManagedObject registrar (takes "ManagedObject" hash 0xBB97DF7D) |

## HealthSubObject + Level3Object — FULL LAYOUT (NEW from clone/ctor decomps)

### HealthSubObject (vtable `0x7FF6D87E24B0`, size ~2 KB+)

Constructor: `sub_7FF6C7F4CF40`. Layout:

| Offset | Field |
|---|---|
| `+0x00` | vtable ptr (`0x7FF6D87E24B0`) |
| `+0x08` | dword/qword = 0 (likely a flag) |
| **`+0x10`** | **Embedded Level3Object** (full struct, ~384 B) |
| `+0x1C0` (448) | WORD = 256 (state flags?) |
| `+0x1C8/+0x1D0` (456/464) | array `{ptr, size_flags}` |
| `+0x1D8` (472) | DWORD |
| `+0x200` (512) | DWORD |
| `+0x240..+0x438` | ~63 zeroed qwords (event-listener slots probably) |
| `+0x440` (1088) | DWORD |
| `+0x480..+0x6B0` | ~62 more zeroed qwords |
| `+0x6C0` (1728) | DWORD |
| `+0x700` (1792) | qword: ptr to 51200-byte pool (128 entries × 400 bytes) |
| `+0x708` (1800) | qword: free-list head (= v3 initially = same as pool ptr) |
| `+0x710` (1808) | DWORD = 128 (entry count) |

So HealthSubObject is the HEAVY container with the event-listener arrays and the **400-byte-entry free-list pool**. The 400-byte entries are likely **damage events** — fits "list of damage records" semantics for tracking history.

### Level3Object (vtable `0x7FF6D8821280`, ~384 B)

Clone function `sub_7FF6C7EEE450`. Layout:

| Offset | Field |
|---|---|
| `+0x00` | vtable ptr (`0x7FF6D8821280`) |
| `+0x08` | dword = 0 — **possible HP int candidate** |
| `+0x10` | (self+16, recursive list-head) |
| `+0x18` | (= a1+16, intrusive list-head self-ref) |
| `+0x20` | vtable `0x7FF6D88AC770` (sub-object) |
| `+0x28` | OWORD = 0 |
| `+0x30` | qword = `0xC0000000` (array capacity-flags) |
| `+0x38` | qword = 0 |
| `+0x40` | `0xFFFFFFFF00000000` |
| `+0x52` | DWORD = `0x10001` (version?) |
| `+0x68` | vtable `0x7FF6D88AC770` |
| `+0x70..+0xA8` | more list-node fields |
| `+0xC0/+0xC8/+0xD0/+0xD8/+0xE0` | array capacity flags `0xC0000000` |
| `+0xE8` | WORD = `0x0101` |
| `+0x120/+0x128` | array `{ptr, size}` of **128-byte records** |
| `+0x130/+0x138` | array of **24-byte records** ← timestamps+amounts? |
| `+0x150` | array of 8-byte |
| **`+0x160`** | **array of 40-byte records** with fields `{qword, dword, byte=-1, ..., byte}` — looks like damage history |
| `+0x180` | DWORD = 0 |

## The 2 wrappers of the chain (NEW)

Two distinct classes BOTH contain the HealthSubObject + Level3Object combo:

### Wrapper 1: DamageComponent (vtable `0x7FF6D88C66D0`, size ≥ 2593 B)
* `[+0x80]` = HealthSubObject embedded
* (chain: DmgComp → +0x80 → HealthSubObject → +0x10 → Level3Object)

### Wrapper 2: UNKNOWN_CLASS_A (vtable `0x7FF6D889D7D0`, size ≥ 2120 B)
Constructor: `sub_7FF6C7CC3620`

* vtable at +0x00 = `0x7FF6D889D7D0` (this class)
* vtable at `+0x38` = `0x7FF6D85C8BB0` (multi-inherit base)
* vtable at `+0x40` = `0x7FF6D89044E0` (HealthSubObject **DERIVED** vtable — different from `0x7FF6D87E24B0`)
* Level3Object at `+0x80` (= 128) initialized via `sub_7FF6C7F4CF40` call
* Has its own 2KB+ fields at `+0x7C8..+0x848` (intrusive-list + tree structures)

So UNKNOWN_CLASS_A is a SECOND container that holds the same HealthSubObject/Level3Object combo at different offsets. Likely **HealthComponent** (a separate component that holds HP, distinct from DamageComponent which holds damage events).

### Possible HP locations (3 candidates)

Based on user's "chain of 3" hint and the observed layouts:

1. **Level3Object[+8]** (dword) — most likely if HP is integer. Init to 0 by clone, would be set to max-HP later. Chain depth: 3 (DmgComp → HealthSub → Level3 → +8).

2. **A field on HealthSubObject after the Level3Object embed** — e.g., HealthSubObject[+0x1C8/+0x1D0] (the array) might be a HP-state array. Chain depth: 2 + final array deref.

3. **Through the DERIVED Level3Object vtable** (`0x7FF6D8821310`) — adds 18 more vfuncs and possibly HP-specific fields beyond base Level3Object's 384 bytes.

Without a live instance to dissect, we can't pick between these. Most plausible by Occam's razor: **Level3Object[+8] = HP** (matches "chain of 3" exactly).




---

## Telemetry pipeline (the trap that wasted a session)

For completeness — this is what `HEALTH:%.2f` actually belongs to:

```
real player state somewhere
    ↓ (28 KB sub_7FF6D3B95010 — upstream)
stack-local "snapshot" struct:
    +0x00  HP float
    +0x04  alive/dead byte
    +0x08, +0x09  flag bytes
    +0x10  context ptr
    +0x18  string ptr (player name?)
    +0x20  ptr
    +0x28  string ptr
    ↓
sub_7FF6D2FB8FB0 — TRACKING RECORD BUILDER (1691 bytes)
    Allocates 6784-byte tracking record at v5.
    Copies snapshot fields into tracking[+0xA88..+0xAB8]:
        tracking[+0xAB8] = snapshot[+0x00]  (HP)
        tracking[+0xAB0] = snapshot[+0x04]  ? "DEAD" : "ALIVE"
    ↓
sub_7FF6D366E890 — telemetry event dispatcher (switch on event-type)
    For most events, calls sub_7FF6D30CA6D0
    ↓
sub_7FF6D30CA6D0 = scimitar::R6TrackingUtil::ConvertToJson
    Reads tracking record, formats as JSON string.
    "HEALTH:%.2f" is the JSON output format.
    ↓
Gameserver telemetry pipeline (Ubisoft Connect / Live Ops)
```

---

## Obfuscation layer summary

* **VMProtect** wraps `.UBX0` (3 MB) and `.UBX1` (129 MB) virtualized sections.
* **MBA wrappers**: ~14k `mov rax, [rip+disp]` → `.data` load sites in 32 MB sample. Top 1% of target globals account for 77.4% of loads (power law). Estimated **5,000-15,000 distinct wrappers** in full binary.
* **Each wrapper** loads 3-4 packed globals + ~200 instructions of MBA (xor/and/lea identities) → indirect call.
* **Runtime key rotation**: packed values change between snapshots (VMP rotates keys).
* **Two-tier dispatch**: small set of shared dispatch tables (e.g. `qword_7FF6D90643E0`, 571 xrefs) + per-wrapper packed values.
* **TLS-keyed gating**: out-of-match paths return early before triggering MBA dispatch.
* **Stripped RTTI**: All Ubisoft R6 classes have RTTI stripped. Only Havok hkReflect/hknp classes preserve MSVC RTTI in `.data`.

---

## Critical caveats / "things to know"

1. **`HEALTH:%.2f` is telemetry** — don't chase it for player HP.
2. **R6CharacterContactFilter has 0 LEA xrefs** — config-driven, not LEA-loaded. Same for `R6_BLOOD_FILTER`.
3. **Most game-side functions ARE MBA-wrapped** — Hex-Rays fails on them. Use disasm + manual analysis.
4. **Bytecode tool live address rebase**: ASLR delta `0x54AC0000` (game pre-rebase) → 0 (IDA matches live now).
5. **Most R6 services register elsewhere** than the 43 names we recovered via direct LEA — many use cached IDs.
6. **The MBA wrapper at RVA 0x4992290** has 0 static callers — only reachable via MBA dispatch tables, so its `rcx` semantics cannot be statically determined.

---

## Open questions

1. **Where is the REAL player HP offset?** (not +0xAB8 of tracking record)
2. **What component is at slot `+0x1E3`?** (most-accessed, paired with +0x1FB)
3. **Per-entity Havok body link** — where on BaseEntity is the actual hknp body handle? (`RigidBodyComponent` is per-world, not per-entity)
4. **Per-frame physics step exact vtable slot** on hknpWorld — known to exist but MBA-hidden.
5. **Cheat-hook `rcx` semantics** at MBA wrapper RVA 0x4992290 — only knowable via dynamic analysis.

---

## File index

* `siegerecon3.md` — THIS file (focused, clean)
* `siegerecon2.md` — full audit trail (4400+ lines, with all retractions / dead ends)
* `SIEGE_RECON.md` — v1 (initial findings)
* `output.md` — earliest scratch
* `live_session_log.json` — Bytecode RPM session log
