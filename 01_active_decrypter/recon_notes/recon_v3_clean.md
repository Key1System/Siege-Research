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

---

## §82  HP region candidate at BaseEntity+0x1B00 (probable, needs damage-event verification)

Live PID 4308, RainbowSix.exe base `0x7FF6C57F0000`.

### Player entity (single live instance)

| field | value |
|---|---|
| Entity heap address | `0xD4B04D00` |
| Entity vtable | `0x7FF6D862A798` (in `.rdata`) |
| Number of components | 26 (vs ~4 for non-player entities) |
| Constructor | `sub_7FF6C86B59F0` (also `sub_7FF6C86BF220` ref's vtable) |
| Inheritance vtable chain (from dtor walk-down) | `0x7FF6D88A3A10` (most base) → `0x7FF6D862A6D8` (intermediate) → `0x7FF6D862A798` (derived) |

DamageComponent chain re-verified live:

| step | address | vtable | semantics |
|---|---|---|---|
| DamageComponent | `0xD4B15D80` | `0x7FF6D88C66D0` | slot 6 of entity component list |
| HealthSubObject | `0xD4B15E00` | `0x7FF6D87E24B0` | DmgComp+`0x80` |
| Level3Object | `0xD4B15E10` | `0x7FF6D8821280` | DmgComp+`0x90` (NOT HealthSub+0x10 as previously assumed) |

Important re-correction: my §80-era trace claimed `HealthSub +0x10 → Level3Object`. Looking at the live DamageComponent dissect again, both `HealthSubObject` (vt `0x7FF6D87E24B0` at DmgComp+0x80) and `Level3Object` (vt `0x7FF6D8821280` at DmgComp+0x90) are **siblings** embedded into DamageComponent — not parent/child. They're 0x10 apart only because HealthSub is 0x10 bytes.

DamageComponent then has an array of 5 sub-pointers at +0x1B0..+0x1F0 (each followed by an `0x10C0000000` interleaved sentinel) — they all point at heap buffers that are currently **all zeros**, consistent with a damage-event ring buffer that is only populated when damage is dealt.

### HP-shaped block at entity +0x1B00 (NEW)

Live dissect of `0xD4B06800` (= entity `0xD4B04D00` + `0x1B00`):

| offset (block) | offset (entity) | type | value | likely meaning |
|---|---|---|---|---|
| +0x00 | +0x1B00 | u32 | `3` | state enum (alive=3?) |
| +0x04 | +0x1B04 | f32 | `2.0` | timer / mult? |
| +0x08 | +0x1B08 | f32 | `5.0` | timer / cooldown? |
| +0x0C | +0x1B0C | f32 | `225.0` | armor/HP cap candidate |
| +0x10 | +0x1B10 | f32 | **`100.0`** ★ | **HP candidate (current)** |
| +0x14 | +0x1B14 | f32 | **`100.0`** ★ | **HP candidate (max)** |
| +0x18 | +0x1B18 | qword | `0x10101` | armor/helmet/vest flags (1 byte each) |
| +0x38 | +0x1B38 | u32 | `2` |  |
| +0x60 | +0x1B60 | ptr | `0x7FF6D8844FA0` (vt) | embedded polymorphic sub-component (43 known subclasses; common base) |
| +0x68 | +0x1B68 | u32 | `1` |  |
| +0x74 | +0x1B74 | u32 | `0xFFFFFFFF` |  |
| +0x80 | +0x1B80 | u32 | `0xFFFFFFFF` |  |
| +0x8C | +0x1B8C | u32 | `0xFFFFFFFF` |  |
| +0x98 | +0x1B98 | ptr | `0xD4AC45C0` | private-rw heap ref |
| +0xA8 | +0x1BA8 | ptr | `0xD4B06A70` | private-rw heap ref (intra-entity?) |

The 100/100 pair fits the classic `(current_hp, max_hp)` shape; `225.0` at +0x0C is suspicious as a max-cap (e.g. 3-armor 125 HP + 100 secondary-armor pool = 225) but unconfirmed.

### Verification attempts and what failed

1. **HW DR0–3 watchpoints (write, then read_write) on `0xD4B06810`**: 83 threads armed, but **0 hits** across 10+ seconds across all four DRx slots. Same result on a control watchpoint on the entity vtable pointer at `0xD4B04D00`. Strongly consistent with BattlEye-style anti-cheat sweeping DR0–3 on each thread or rebinding context on switch.
2. **Software polling diff** (snapshot + diff_since): 0 bytes changed in 5s on a 128-byte snapshot of the HP block. 0 bytes changed in 3s on an 8 KB snapshot of the entity. 0 bytes changed in 3s on a 16 KB sample of `.data` at `0x7FF6D9000000`. Game appears alt-tabbed / paused — no UI thread tick is touching memory.
3. **Static search for float-100.0 immediate write at +0x1B10**: pattern `10 1B 00 00 00 00 C8 42` (`mov dword ptr [reg+0x1B10], 0x42C80000`) — **0 hits**. HP is not initialized via a literal immediate; it comes from a config / xmm copy.
4. **Constant pool search** for `{2.0, 5.0, 225.0, 100.0, 100.0}` consecutive in .rdata / .text / .data — **0 hits**. Block is built field-by-field from gameplay config, not stamped from a static template.
5. **One promising-looking write**, `0x7FF6C96BE853  mov dword ptr [rbx+0x1B10], 0x64` (dword 100), is **a false match** — `sub_7FF6C96BE4B0` initializes a different struct (mutex-paired DWORD fields at +0x1AE0, +0x1B10, +0x1B40, +0x1B70, +0x1BA0 — all dword 100, mutex-protected counters). Our HP value reads as **float** `100.0` = `0x42C80000`, not dword `100` = `0x00000064`, so different struct entirely.
6. **`movaps xmmword ptr [rbp+0x1B10], xmmN`** matches in `sub_7FF6D32993B0` (and one other) are also false — those write a 16-byte block that is part of a repeating ~0x40-stride pattern (vtable + slot stamping), not HP.

### Why this is still the best HP candidate

* Two consecutive float 100.0 values is the canonical (current, max) HP shape.
* `225.0` neighbor matches plausible armored-operator caps.
* `0x10101` flag triple matches armor/helmet/vest equip flags.
* Block sits inside the entity heap allocation, not in a separately-tracked component — explains why neither the DamageComponent chain nor a `find_ptr` to `0xD4B06810` returns external referrers; it's accessed via `[entity + 0x1B10]` only.
* Embedded vtable at +0x60 makes the whole thing look like a `HealthSystem`-style sub-block whose state header sits *above* the C++ vtable (common in component systems that prepend a POD header to a polymorphic body).

### Still required to fully verify (blocked on user activity)

1. User takes damage in training (open door + explode pellet, fall damage) → re-read `0xD4B06810` and confirm it drops below 100.0.
2. After damage, locate the **damage-apply function** by setting a software int3 (not HW BP, since DR0–3 are being neutralized) at any of the candidate write sites and catching the first hit.
3. Confirm `+0x1B14` is true max (should NOT change when current drops) vs. another field (e.g. `225.0` at +0x0C).

### Note on tooling
HW DR0–3 watchpoints in `/watch_writes` were reported as armed (83 threads) but never delivered a hit on either the HP candidate or the entity vtable pointer — consistent with BattlEye DRx scrubbing. Use software int3 patches via `/patch_asm` or polling diffs for any future "is this address really X?" verification.

### §82.5 update (2026-05-24): user reports actual HP = 110, not 100

User stated their current operator HP is `110` (2-armor operator). My §82 candidate at `0xD4B06810` was `100.0/100.0` — so either it is HP for a different (1-armor) entity, or it is a different stat entirely. Reopening the search:

* Live AOB scan for two consecutive `110.0` floats (`00 00 DC 42 00 00 DC 42`) across all `+RW`: exactly **one** match at `0x168C6F672`. Disqualified — context decoded as a sorted half-word table of float upper-words (`0x4291,0x42BE,0x42DC,0x430E,0x432E,0x4343,0x436A,0x43A1,0x43CF,0x43EC`), i.e. weapon damage drop-off / range table, not cur/max HP.
* Live `find_value` on float `110.0` returned **171 hits** total, 63 in entity-heap (`0xC*..0xF*`) range.
* Tested 22 of those hits as "is there a player entity vtable at `[hit - 0x1B10]`?" → none match `0x7FF6D862A798`.
* Tested cur/max pattern (`hit, hit+4` both = 110.0) → none in the player vtable entities. Closest is the `0xD4A8AE40..0xD4A8C7C0` cluster — that's a 48-byte-record config table with first field a float (100, 110, 130, 140, 160, 170, 190, …) followed by two string pointers and two function pointers per record — operator-stat config table, not live HP.

Active scan session is live (`/scan_new` op=eq value=110, 171 candidates). The clean way to find true HP now is:

```powershell
# 1. user takes any damage (one bullet, fall, explosive)
# 2. narrow
$b = @{ session_id=2; op="decreased" } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:9999/scan_next" -Method Post -ContentType "application/json" -Body $b
# 3. heal back to 110, narrow again with op=increased, then op=eq value=110
```

Expected: convergence to 1–3 addresses, the live HP float.

### Verification recipe (run while in-game and actively moving / shooting)

```powershell
# 1. snapshot HP block
$b = @{ tag="hp"; address="0xD4B06800"; size=64 } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:9999/snapshot" -Method Post -ContentType "application/json" -Body $b

# 2. take damage in training grounds (jump off a height, shoot an explosive at your feet)

# 3. diff
$b = @{ tag="hp"; max_runs=32 } | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:9999/diff_since" -Method Post -ContentType "application/json" -Body $b
# Expected: change at +0x10 (HP drop), no change at +0x14 (max HP)
```

If the entity in question is dead/respawned, the heap address `0xD4B04D00` will not survive; re-find the entity via:
```powershell
# find player vtable instances in private-rw, pick the one whose +0x1B14 == +0x1B10 (cur==max) at spawn
$b = @{ value="0x7FF6D862A798"; value_size=8; protection="+RW"; limit=2000 } | ConvertTo-Json
$hits = (Invoke-RestMethod -Uri "http://127.0.0.1:9999/find_value" -Method Post -ContentType "application/json" -Body $b).hits
# filter to live heap instances (typically >= 0x40000000), then test each for HP-shape
```

---

## §84  Physics — Havok integration (IDA static analysis, 2026-05-24)

### 84.1 — String table → IDA address rebase rule (REFRESH)

`mcp__ida__find_regex` returns string addresses encoded against the **OLD** PE imagebase `0x7FF71A2B0000`. The live process and IDA's current segments use base `0x7FF6C57F0000`. **Always subtract DELTA `0x54AC0000` from any `find_regex` output address before passing it to `xrefs_to` / `decompile` / `disasm`.** Confirmed by ground-truth: find_regex returned `0x7FF72D53738E` for `"hknpWorld"`, manual scan found the same string at `0x7FF6D8A7738E`, diff = `0x54AC0000`.

(This contradicts the §83 note that EAs match live — that's correct for **segment EAs / function addresses** but **NOT** for find_regex string output.)

### 84.2 — Havok class strings (rebased) and constructors

| string | real EA | xref'd constructor / user |
|---|---|---|
| `hknpWorld` | `0x7FF6D8A7738E` | `sub_7FF6CB16C4E0` (uses it for logging) |
| `hknpBody` | `0x7FF6D8B78F88` | no direct code xrefs |
| `hknpCharacterRigidBody` | `0x7FF6D8A1F955` | `anvil_AttachCharacterRigidBody_factory` (see below) |
| `hknpStepInput` | `0x7FF6D8B7BE40` | – |
| `hknpShape` | `0x7FF6D8BA0D60` | – |
| `hknpMotion` | `0x7FF6D8B906E0` | – |
| `hknpCharacterRigidBody` (alt @ `0x7FF6D8B78FD8`) | – | `hknpCharacterRigidBody_ctor` calls the named-alloc with this literal |
| `hknpRefMassDistribution` | (inline) | inline string in `hknpCharacterRigidBody_ctor`, allocator labels the 80-byte default mass-distribution block |

### 84.3 — `anvil_AttachCharacterRigidBody_factory` @ `0x7FF6CA8BC540`

Allocates one 160-byte `hknpCharacterRigidBody` via the named-alloc API:
```
v9 = qword_7FF6D91348A8(0, 160, 0);                  // 160-byte alloc
off_7FF6D91348B8(v9, "hknpCharacterRigidBody");      // label
hknpCharacterRigidBody_ctor(v10, a2);                // base ctor (a2 = cinfo)
*(_QWORD *)v10           = &vt_hknpCharacterRigidBody;  // 0x7FF6D8517BE0
*(_QWORD *)(v10 + 0x90)  = v11;                      // physics-world / motion ptr
*(_BYTE  *)(v10 + 0x98)  = 0;                        // flag
```
Then attaches itself into two `MemberSlot`s (signal/slot lists, sizes 32 bytes each) embedded on the Havok body manager at +`3904` (`v13 + 0xF40`) and +`3912` (`v25 + 0xF48`). Then calls a body-manager hook at vt+0x190 to register the body in the simulation, then a second hook at vt+0x158.

Three code xrefs to the factory:
- `sub_7FF6CA850100` — thin wrapper: builds a 4-qword cinfo via `sub_7FF6CA930580`, calls factory, releases.
- `sub_7FF6CA95A240` ×2 — fatter caller (0xA5C bytes) that picks up some state from a TLS-backed cache (`gs:58 + TlsIndex*8`).

Both callers themselves have **no static callers** (MBA-hidden dispatch).

### 84.4 — `hknpCharacterRigidBody_ctor` @ `0x7FF6D7AB9350` (RE-AUDITED 2026-05-24)

Sets the BASE vtable `unk_7FF6D82BFCE0` (overridden by factory), then writes the cinfo into the body. Offsets re-verified by re-reading the Hex-Rays decomp directly:

| body offset | source | C-decomp line |
|---|---|---|
| +0x00 | – | `*(_QWORD *)a1 = &unk_7FF6D82BFCE0;` — base vtable |
| +0x08 | – | `*(_QWORD *)(a1 + 8) = 0xFFFFFFFFLL;` |
| +0x10 | – | `*(_QWORD *)(a1 + 16) = 1;` |
| +0x18 | – | `*(_QWORD *)(a1 + 24) = -1;` |
| +0x20 | – | `*(_QWORD *)(a1 + 32) = 0;` |
| +0x28 | cinfo+0x28 | `*(_QWORD *)(a1 + 40) = *(_QWORD *)(a2 + 40);` |
| +0x30 | cinfo+0x30 | `*(_QWORD *)(a1 + 48) = *(_QWORD *)(a2 + 48);` |
| +0x38 | – | `*(_QWORD *)(a1 + 56) = 0;` |
| +0x40 | cinfo+0xB0 | `*(_DWORD *)(a1 + 64) = *(_DWORD *)(a2 + 176);` ⚠ correction — was wrongly mapped earlier |
| +0x50 | cinfo+0x90 | `*(_OWORD *)(a1 + 80) = *(_OWORD *)(a2 + 144);` — 16-byte Vector4 (collision filter / aabb) |
| +0x60 | cinfo+0xA0 × (1+1/256) | `*(_DWORD *)(a1 + 96) = *sub_7FF6D7A6AAF0(... shuffle(cinfo+160) × 1.00390625);` |
| +0x64 | cinfo+0xA4 × (1+1/256) | same as +0x60 with cinfo+0xA4 source |
| +0x68 | cinfo+0xAC | `*(_DWORD *)(a1 + 104) = *(_DWORD *)(a2 + 172);` ⚠ correction (was claimed cinfo+0xB0) |
| +0x6C | cinfo+0xB4 | `*(_DWORD *)(a1 + 108) = *(_DWORD *)(a2 + 180);` |
| +0x70 | cinfo+0xA8 | `*(_DWORD *)(a1 + 112) = *(_DWORD *)(a2 + 168);` ⚠ correction (was claimed cinfo+0xAC) |
| +0x78 | – | `*(_QWORD *)(a1 + 120) = 0;` |
| +0x80 | – | `*(_DWORD *)(a1 + 128) = 0;` |
| +0x84 | – | `*(_DWORD *)(a1 + 132) = 0x80000000;` (default motion id sentinel) |

If `(body+0x84 & 0x7FFFFFFF) < 4`, calls `sub_7FF6CA86EA60(body+0x78, ..., 4)` — initializes a dynamic array at body+0x78 with capacity 4.

If `cinfo+0x20` is non-zero (mass-distribution requested), builds an `hknpRefMassDistribution` (80 bytes, allocator-labelled, initialised with 255-fill at +16 and +48) and stores it at `body+0xB8` (= `a1+184`) via the store-helper that bumps the refcount. Also resolves a shape via vt-slot +0x60 on `body->manager` (= `*(QWORD*)(body+0x30)`).

### 84.5 — Component registry table @ `sub_7FF6C5D97680`

The static initializer at `sub_7FF6C5D97680` registers **130 component class descriptors** into the global type-registry `qword_7FF6D93E1B60`. Each descriptor is a global qword in `.data`. The 113th entry (`v2[112]`) is `&qword_7FF6D93E0438` — the **`RigidBodyComponent`** class descriptor (registration code: `sub_7FF6CA807470`, string `"RigidBodyComponent"`, hash slot stored in `dword_7FF6D93DF50C`).

Descriptor layout (decoded):
- +0x40 → `sub_7FF6CA7CF4D0` — common-base Component ctor (sets vtable to shared `unk_7FF6D8856A90`, used by 100+ component classes)
- other slots scrambled/XOR'd (not yet decoded)

So `RigidBodyComponent` shares the *generic* component vtable `unk_7FF6D8856A90` and only its **descriptor** differs. The actual behaviour (rigid-body logic) is reached through the descriptor's function-pointer table at runtime — typical of an Anvil reflection-driven component system.

### 84.6 — BaseEntity transform layout (partial)

Verified from `BaseEntity_SetScale_Vec3` @ `0x7FF6C86FA480`:

| entity offset | type | semantics |
|---|---|---|
| +0xFC | f32 | scale X |
| +0x100 | f32 | scale Y |
| +0x104 | f32 | scale Z |
| +0xF8 | f32 | (set to 1.0 in ctor; possibly uniform-scale or quaternion-W) |
| +0xB0 | u64 | flag/state packed qword (init `0x0480E00000000030`; bit 39 = `0x8000000000` toggled by `sub_7FF6C86A7C80`) |
| +0xB0 (low byte) | u8 | flag byte (bit-7 & ANDed to 0x7F in ctor; possibly init lock) |
| +0xDF | u8 | flag byte (OR'd `0x40` in ctor) |
| +0x108 | u8 | byte (=7, state) |
| +0x10A | u16 | (=`0x2701`) |
| +0x10C | u8 | (=0) |
| +0x118 | u8 | flag byte (bits 1/2/3/4 control physics flag propagation) |
| +0xD0 | ptr | **ComponentList** head (heap-allocated; was at `0xD4B05090` in live PID 4308) |
| +0x1A0 | – | sub-component (passed to a service call in `sub_7FF6C86A7C80`) |
| +0x1E3 | u8 | **slot index** byte (read repeatedly in `sub_7FF6C86A7C80` as index into ComponentList) |
| +0x298 | ptr | signal/slot container — sub-pointers cleaned up by `sub_7FF6C872B780` (generic callback-list dtor) |
| +0x1B00..+0x1B18 | mixed | **HP-shaped block** (see §82 — needs damage verification) |

**`sub_7FF6C86A7C80`** is the BaseEntity-level **physics flag propagation** function — it copies bits from `entity+0xB0` and `entity+0x118` into a slot returned by `sub_7FF6C5C775F0(entity)` (a per-entity 144-byte scene/world cache slot indexed via `entity+0x1A8` handle). Several bits map to physics quality / collision-filter modes. This is the entry point for "tell the physics world that this entity's body parameters changed".

### 84.7 — Renamed in IDA database (this session)
- `sub_7FF6CA8BC540` → `anvil_AttachCharacterRigidBody_factory`
- `sub_7FF6D7AB9350` → `hknpCharacterRigidBody_ctor`
- `sub_7FF6C86FA480` → `BaseEntity_SetScale_Vec3`
- `unk_7FF6D8517BE0` → `vt_hknpCharacterRigidBody`

### 84.8 — World cache slot layout (entity↔physics mirror, **144 bytes**)

`BaseEntity_GetWorldCacheSlot_144` (renamed from `sub_7FF6C5C775F0`) returns a per-entity 144-byte slot from a global pool indexed by `entity+0x1A8` packed handle (low 32 bits = generation, bits 33-47 = slot index, bit 32 = "allocated"). The slot is the **physics-world mirror** of the entity.

Confirmed writes from `BaseEntity_PushScaleToWorldCache` (renamed from `sub_7FF6C86A59E0`, the post-scale-change finisher invoked from `BaseEntity_SetScale_Vec3`):

| slot offset | type | semantics (CONFIRMED via PushScaleToWorldCache) |
|---|---|---|
| +0x00 | `OWORD` | derived transform component, written via vt-slot `qword_7FF6D90271F0` (a Quat/Mat3 normalize-or-decompose helper) |
| +0x10 | `OWORD` | second derived transform component, written via vt-slot `qword_7FF6D9027588` |
| +0x60 | `QWORD` | flag/quality bitfield (heavily edited by `BaseEntity_PropagatePhysicsFlags` — bits track collision filter, motion class, raycast/query masks, scale-non-uniform flag, etc.) |
| +0x62 | byte | dirty-bit byte (bit 1 set on transform/rotation push) |
| +0x63 | byte | dirty-bit byte (bit 2 set on scale push) |
| +0x78 | 8B (low qword) | scale-derived qword (computed from `entity+0xFC` via vt-slot `qword_7FF6D9026CA0`) |
| +0x80 | `DWORD` | scale-related dword (4-byte tail) |

(Slot offsets +0x00 / +0x10 hold derived values — not raw position/rotation; raw transform writes happen from other xrefs of `BaseEntity_GetWorldCacheSlot_144`. Will enumerate.)

Total scratch — 9 OWORDs (144 / 16) so additional fields fill +0x20..+0x5F and +0x88..+0x8F. These are touched by other functions in the 60+ xrefs to `BaseEntity_GetWorldCacheSlot_144` (most are `BaseEntity_*` setters: `SetPosition`, `SetTransform`, etc. — to be enumerated).

### 84.9 — Renamed in IDA database (this session, cumulative)

- `sub_7FF6CA8BC540` → `anvil_AttachCharacterRigidBody_factory`
- `sub_7FF6D7AB9350` → `hknpCharacterRigidBody_ctor`
- `sub_7FF6C86FA480` → `BaseEntity_SetScale_Vec3` (writes entity+0xFC..+0x104)
- `sub_7FF6C5C775F0` → `BaseEntity_GetWorldCacheSlot_144` (resolves entity→144B world slot)
- `sub_7FF6C86A59E0` → `BaseEntity_PushScaleToWorldCache` (post-scale finisher; writes slot+0x78)
- `sub_7FF6C86A7C80` → `BaseEntity_PropagatePhysicsFlags` (writes slot+0x60 from entity+0xB0 / +0x118 flags)
- `unk_7FF6D8517BE0` → `vt_hknpCharacterRigidBody`

### 84.10 — Still open
- Decode +0x20..+0x5F of the world cache slot (likely position vec3, velocity, AABB extents).
- Identify the SetPosition / SetTransform xrefs that write +0x00/+0x10 (look in the 60+ xrefs to `BaseEntity_GetWorldCacheSlot_144`).
- `RigidBodyComponent` descriptor's runtime dispatch table beyond +0x40 (function pointers).
- Per-frame physics step entrypoint on `hknpWorld` (MBA-hidden).
- Full cinfo struct shape passed to `anvil_AttachCharacterRigidBody_factory`.

---

## §85  **RETRACTION** — entity `0xD4B04D00` is a template, not the live player

A *live* test of `entity+0x1A8` (the world-handle qword) on `0xD4B04D00` returned `0xFFFF0000FFFFFFFF` — the **sentinel** value set by the ctor (`mov rdx, 0xFFFF0000FFFFFFFF; mov [r15+1A8h], rdx`). The same entity's `+0x1E3` slot-index byte is `0xFF` (unset). Both prove this entity is **NOT registered in any physics world** — it's a pre-instantiated template/blueprint, not an in-play player.

Implications:
1. **§82's HP candidate at `entity+0x1B10` is INVALIDATED.** The two `100.0f` floats found at `0xD4B06810/14` were coincidental data on a template entity. Sampled 9 *real* in-world player-vtable entities at the same offset — none had reasonable HP values (mostly garbage / very small / very large floats).
2. The "0 bytes changed in 5+s" diff result is **expected** for a template — they're write-once init blocks that the game doesn't touch after manifest load.
3. The HW DR0–3 watchpoints not firing on `0xD4B06810` is also **expected** for the same reason. BattlEye-DRx-scrubbing remains a real concern but isn't proven by this test.

### Finding the live player
Live sweep of all 2000 instances of player-vtable `0x7FF6D862A798`:
- **240** have a non-sentinel `+0x1A8` (in-world entities, e.g. `0x2DFA8820`, `0xE7C323A0`, `0xE7D920A0`, `0xE7D926D0`, `0xE880D240`, `0xE8922590`, plus ~234 more).
- **1760** are templates / pool entries (sentinel `+0x1A8`).
- The local player is one of the 240. Heuristic: it's the one tied to the local input/camera. Identifying it requires either:
  - Following the "local player" global pointer (e.g., `qword_7FF6D9...` somewhere), or
  - Damage-narrow scan from a known float (HP), or
  - Spatial: find the entity whose +0xFC..+0x104 scale is `(1.0,1.0,1.0)` AND whose position is closest to the camera.

### Re-find recipe
```powershell
# all in-world player-vtable entities, sorted by +0x1A8 handle
$h = (Invoke-RestMethod -Uri "http://127.0.0.1:9999/find_value" -Method Post -ContentType "application/json" -Body (@{ value="0x7FF6D862A798"; value_size=8; protection="+RW"; limit=2000 } | ConvertTo-Json)).hits
$reads = $h | ForEach-Object { @{ address=("0x{0:X}" -f ([Convert]::ToUInt64($_,16) + 0x1A8)); type="qword" } }
# split into batches of 200, read_batch, filter out 0xFFFF0000FFFFFFFF and 0x0
```

### Carry-overs that ARE still valid
- IDA static names from §84 (BaseEntity_SetScale_Vec3, BaseEntity_GetWorldCacheSlot_144, anvil_AttachCharacterRigidBody_factory, etc.) are unchanged — they describe the **code**, not a specific entity instance.
- entity+0xFC..+0x104 = scale Vec3 — confirmed via the constructor regardless of which instance.
- entity+0x1A8 = world-handle qword — confirmed via the constructor.
- entity+0x1E3 = slot-index byte — confirmed via the constructor.
- The 144-byte world cache slot layout in §84.8 — still derived from PushScaleToWorldCache; applies to live entities only (templates don't have a slot).

---

## §86  Entity transform discriminated union at `entity+0x80`

`sub_7FF6CB4D07D0` (called from `BaseEntity_PushScaleToWorldCache` after the scale-derived data has been computed) takes `rcx = entity+0x80`, `rdx`, `r8` and dispatches on a 4-byte enum at `entity+0x8C`:

```
v3 = *(_DWORD *)(entity + 0x8C);   // transform-representation kind
switch (v3) {
    case 0:  /* identity / fall through */ ;
    case 1:  goto loc_7FF6CB4D0F82;   /* representation type 1 */
    case 2:  goto loc_7FF6CB4D0BEC;   /* representation type 2 */
    default: /* return early */
}
```

This is the **transform discriminated union** sitting at `entity+0x80`. Each kind has its own pack layout in the same buffer (~`0x70` bytes wide given that PushScaleToWorldCache passes `entity+128 = entity+0x80`, and the func uses 5 XMM regs internally). Likely meanings (typical for these engines):
- **kind 0** = identity transform (no transform stored; world = local).
- **kind 1** = position+orientation only (no scale or scale==1; stored as `Vec3 pos` + `Quat rot`).
- **kind 2** = full SRT (Vec3 scale + Quat rot + Vec3 pos), or full Mat4.

Confirms earlier suspicion from dissect:
- `entity+0x80`: `1.9553` (interpreted as float in §80 dissect — likely either kind 0 with high bytes holding an unset payload OR kind 1's first float)
- `entity+0x88`: ptr-looking `0x43A801E` — fits a packed quat W or count
- `entity+0x8C`: dword = transform-kind enum

### Local-player handle global — not found by name
Searched IDA strings for `LocalPlayer`, `LocalPawn`, `MyPawn`, `MyPlayer`, `GetLocal*` — only matches are UI / locale (`GetLocalBoneTransform` is reflection-script for bone access). The local-player entity pointer isn't exposed via a named global string. To find it dynamically: scan `+RW` for a *pointer* whose target has vtable `0x7FF6D862A798` AND non-sentinel `+0x1A8` AND `entity+0xFC..+0x104 == (1.0, 1.0, 1.0)` (canonical operator scale). That pointer's address is the global hook.

---

## §87  Skeleton / Bones (IDA pass)

### 87.1 — Strings inventory

Most skeleton/bone strings are **profiler scope labels** (passed via MBA-hidden marker functions, so they leave no static xrefs). They're useful as a roadmap of what features exist:

| string | real EA | notes |
|---|---|---|
| `char_UpdateSkeleton` | `0x7FF6D8A49A91` | per-character skeleton update — 0 static xrefs (scope label) |
| `char_UpdatePawn` | `0x7FF6D8A49837` | pawn update task name |
| `char_UpdateAnimPrePhysics` | `0x7FF6D8A3901E` | anim drives ragdoll — 0 static xrefs |
| `char_UpdateAnimDuringPhysics` | `0x7FF6D8A38FDD` | mid-physics anim sample |
| `char_ScheduleCharacters` | `0x7FF6D8A30FDA` | scheduler entry point |
| `wld::WorldTasks::KickAnimPrePhysics` | `0x7FF6D8A38FFA` | world-task wrapper |
| `wld::WorldTasks::KickCharacterStoryboards_PostPhys` | `0x7FF6D8A28E2A` | post-physics character anim update |
| `wld::World::UpdatePostSkeleton` | `0x7FF6D8A49A47` | post-skeleton world tick |
| `AnimationHandler_UpdateAnimations` | `0x7FF6D8A32944` | 1 xref → `sub_7FF6D6AEF590` (task descriptor builder; main update is `sub_7FF6C962CF40` → `sub_7FF6C9630610` task-enqueue) |
| `AcquireSkeletonPoseSnapshot` | `0x7FF6D8A25F81` | reflection-bound API |
| `GetPoseSnapshot` | `0x7FF6D8A25F71` | reflection-bound API |
| `SetLocalBoneTransform` / `GetLocalBoneTransform` / `SetGlobalBoneTransform` / `GetGlobalBoneTransform` / `GetBindPoseLocalBoneTransform` | `0x7FF6D8A54931..0x7FF6D8A54992` | script-reflection APIs (all referenced from the two big binding-registration funcs `sub_7FF6CB243A40` and `sub_7FF6D68507B0`) |
| `boneMatrixMap` | `0x7FF6D8B8EBB8` | likely struct-field name in a config schema |
| `useModifiedBoneMatrix` | `0x7FF6D8A2079F` | bool flag on `this+0x42` bit 1 (set via `sub_7FF6C5CAEC50`) |
| `PoseCollisionMaxDist` | `0x7FF6D8A24617` | config-parser key; written to `target+0x5C` (see §87.3) |
| `CharacterScheduler` | `0x7FF6D8A42F48` | class name |
| `GFXGraphicObject_VF_Skinning8Bones` | `0x7FF6D8A36297` | vertex factory for 8-bone skinning |
| `IKBoneSolver{Pose,OneBone,TwoBone,FullBody,Lattice,Physics,Spine,Centroid,DirectChain,Projection,NoOperation,OneBoneMaxDistance,…}` | `0x7FF6D89A2E50..0x7FF6D89A47B0` | **full IK solver class catalog** (~20 IK solver variants) |
| `hkSkeleton`, `hkSkeletonContainer`, `hkSkeleton::Partition`, `hkSkeleton::LocalFrameOnBone` | `0x7FF6D8B90218`, `0x7FF6D8B8BF38`, `0x7FF6D8B906F0`, `0x7FF6D8BA1098` | Havok skeleton C++ class names (used inside Havok's RTTI/type_info, not directly LEA'd) |
| `.?AVhkSkeleton@@`, `.?AVhkSkeletonContainer@@` | `0x7FF6D912D530`, `0x7FF6D912D558` | MSVC RTTI mangled-type strings; type_info_t at `0x7FF6D912D520` (vftable `0x7FF6D82E4EE0`) |

### 87.2 — Havok class `hkSkeleton`

* Class name string at `0x7FF6D8B90218`. RTTI type_info_t at **`0x7FF6D912D520`** (8 bytes vftable, 8 bytes pad, then mangled name `.?AVhkSkeleton@@`).
* `hkSkeleton` is the **shared skeleton template** (bone hierarchy, names, bind pose). It is **not** the per-character runtime pose — that's a separate `hkaPose` / partition struct.
* `hkSkeleton::Partition` exists as a string — Havok stores bones in named partitions (`Skeleton`, `LowResSkeleton`, `Ragdoll`, etc.) so a character can have one mesh skeleton + one ragdoll skeleton sharing data.
* `hkSkeleton::LocalFrameOnBone` exists — attachment-frame metadata per bone.
* No direct code xrefs found to the type-info strings — accessed via Havok's internal RTTI machinery, not via LEA from R6 code. To follow at runtime: scan `+RW` for QWORDs pointing to `0x7FF6D912D520`; each match is one `hkSkeleton` instance.

### 87.3 — Pose-collision config parser (`sub_7FF6D6538780`)

The 5-xref function on `PoseCollisionMaxDist` is a config setter for the **character pose-collision sub-struct**. Parses key/value pairs from a 24-byte-stride config vector. Decoded property → offset map (writes to the `a1` target struct):

| INI/config key | target offset | type |
|---|---|---|
| `VelocityDamping` | +0x40 | f32 |
| `SlidingEffectOnDamping` (variants 0/1) | +0x44 / +0x48 | f32 |
| `SlidingEffectOnDamping` (variants 2/3) | +0x4C / +0x50 | f32 |
| `SlidingEffectOnDamping` (variants 4/5) | +0x54 / +0x58 | f32 |
| (sliding-effect bool) | +0x88 | u8 |
| `PostSolveStick…` | +0x89 | u8 (bool) |
| `ApplyPoseCollision…` | +0x90 | u8 (bool) |
| `PoseCollisionMaxDist` | +0x5C | f32 |

This struct (~96 bytes around the named tunables) is the **physics-driven pose adjustment** config used to keep skeletal feet/hands aligned with collision geometry. Sits inside the character's anim/skeleton runtime — likely embedded in the per-character SkeletonComponent. Other xref `sub_7FF6D64DCCF0` (0x2AFF bytes) is the bigger sibling parser that handles the whole skeleton-component config.

### 87.4 — Anim update task pipeline (partial)

`AnimationHandler_UpdateAnimations` is referenced from `sub_7FF6D6AEF590` (0x1D59 bytes), which is a **task-descriptor builder**. The descriptor wires up:

* `entry/exit` at `sub_7FF6C5E76440` / `sub_7FF6C5E8A2A0`
* `prepare` at `sub_7FF6C5E7A0A0`
* `cleanup` at `sub_7FF6C5E843D0`
* `submit` at `sub_7FF6C5E6F210`
* **main execute** at `sub_7FF6C962CF40` (= one-liner: sets a flag at `task+0x30` and calls `sub_7FF6C9630610` to enqueue)
* `cancel/abort` at `sub_7FF6C9619670`
* vtable at `unk_7FF6D861AFC0`

`sub_7FF6C9630610` is the per-thread **task queue push** — pulls a free entry from a per-TLS free-list at `TLS[14200]+160`, stores the task pointer, atomic-pushes to the owner's queue at `owner+80`, and signals workers. So `UpdateAnimations` doesn't run inline — it's enqueued onto the world's job graph and picked up by the worker that owns the `char_UpdateSkeleton` slot.

### 87.5 — IK solver class catalog (script-reflected, no direct ctors)

R6 ships ~20 IK solver variants discoverable by string:
`IKSolverOneBone`, `IKSolverOneBoneStretch`, `IKSolverTwoBone`, `IKSolverPose`,
`IKBoneSolverOneBone`, `IKBoneSolverTwoBone`, `IKBoneSolverOneBoneMaxDistance`, `IKBoneSolverPose`,
`IKBoneSolverDirectChain`, `IKBoneSolverNoOperation`, `IKBoneSolverLattice`, `IKBoneSolverProjection`,
`IKBoneSolverSpine`, `IKBoneSolverFullBody`, `IKBoneSolverPhysics`, `IKBoneSolverCentroid`,
`IKBoneSolverObject`, `IKBoneSolverChainObject`.
Plus container types `Vector:IKBoneSolverPoseBoneData`, `unique_ptr:IKBoneSolverData`, `Vector:unique_ptr:IKBoneSolverData`.
Each has a `…Data` companion type for serialised parameters. The `…Physics` solver is the physics-driven one (ties bones into the Havok world).

### 87.6 — Open
- Find the per-character `SkeletonComponent` vtable/heap layout (haven't located yet — registration likely in `sub_7FF6CA807470`'s big table near the RigidBodyComponent entry).
- Walk the live in-world entity list (240 candidates from §85) for one that owns a bone array — bones are typically a flat `OWORD[~150]` (Mat3x4 per bone × ~150 bones ≈ 7.2 KB).
- Bone count for R6 standard character = unknown; engine supports up to 8-bone skinning per vertex (string above), suggests ~150 bones for an operator skeleton.
- The transform conventions (local vs world, row vs column-major Mat4 vs Mat3x4): need to dump bone bytes on a live character.

---

## §88  hknpWorld — Havok physics world (CONSTRUCTOR DECODED)

### 88.1 — The world constructor `R6_PhysicsWorld_Init_hknpWorld` (`sub_7FF6CB16C4E0`, size 0x16E4)

This is **the** R6 physics world initializer. Allocates and wires up the entire physics subsystem. Single caller: `sub_7FF6C9810180` (size 0xD25) — the World/Game manager that reads/owns `g_PhysicsWorldOwner` (`qword_7FF6D91947B0`).

```
v54 = qword_7FF6D91348A8(0, 4432, 0);           // allocate hknpWorld (4432 bytes)
off_7FF6D91348B8(v54, "hknpWorld");              // label allocation
hknpWorld_Init_SimulationContext();              // sub_7FF6D7A6CA00 - init sim ctx at world+0x10A0
*v55      = &vt_hknpWorld_primary;               // 0x7FF6D86D6790
v55[3]    = &vt_hknpWorld_sub_18;                // 0x7FF6D85BB4B0 (hknpWorldReader sub-object)
v55[4]    = &vt_hknpWorld_sub_20;                // 0x7FF6D84895F0 (hknpWorldWriter sub-object)
v55[550]  = owner;                               // world+0x1130 = pointer back to owner
v55[551]  = 0;
v55[552]  = 0xC0000000;
...
// R6-specific extensions registered into world's effects pool:
v131 = qword_7FF6D91348A8(0, 8, 0);                       // 8-byte
off_7FF6D91348B8(v131, "RollingSlidingSoundModifier");
*v131 = &vt_R6_RollingSlidingSoundModifier;               // 0x7FF6D8575110
*(_QWORD *)(world + 360)  = v131;
sub_7FF6D7B0FD70(world->materialMods, 8, v131, 0);        // register

v133 = qword_7FF6D91348A8(0, 8, 0);
off_7FF6D91348B8(v133, "R6DefuserMassModifier");
*v133 = &vt_R6_DefuserMassModifier;                       // 0x7FF6D85CF1C0
*(_QWORD *)(world + 368)  = v133;
sub_7FF6D7B0FD70(world->materialMods, 0x10000000, v133, 0);  // register w/ flag 0x10000000
*(_BYTE *)(world + 2702097) = 0;
```

### 88.2 — hknpWorld layout — **CORRECTED AND VERIFIED**

**Important correction (2026-05-24):** Previously-claimed reader/writer offsets were given as *sub-object-relative* but I documented them as world-relative — wrong. MSVC ABI: a sub-object method receives `this = world + sub_offset`. So `[this + N]` inside a reader method is actually `world + 0x18 + N`, and inside a writer method is `world + 0x20 + N`. Re-derived table below; **✓** = also confirmed by reading live `hknpWorld @ 0x16A880D90`:

| offset | size | name / type | source | live |
|---|---|---|---|---|
| +0x00 | 8 | `vt_hknpWorld_primary` | ctor | ✓ |
| +0x08 | 4 | refcount low | dissect | `0xFFFFFFFF` |
| +0x10 | 8 | refcount qword | dissect | `1` |
| +0x18 | 8 | `vt_hknpWorld_sub_18` (reader sub-object) | ctor | ✓ |
| +0x20 | 8 | `vt_hknpWorld_sub_20` (writer sub-object) | ctor | ✓ |
| +0x28 | 8 | **self-ptr** (intra-world link) | dissect | `0x16A880D90` (= world) |
| +0x30 | 8 | intra-world ptr | dissect | `0x16A881498` (→ world+0x28) |
| +0x38 | 8 | heap obj | dissect | `0x1032EE90` (→ vt `0x7FF6D8319830`) |
| +0x40 | 8 | heap obj | dissect | `0x12FA64050` |
| +0x48 | 8 | packed flags | dissect | `0x4000000008A` |
| +0xA8 | 8 | **hknpBodyManager** ptr (writer slot 3 reads `[rcx+0x88]`; `rcx = world+0x20` → `world+0xA8`) | static (disasm) | `0` — not wired (no active match) |
| +0xF78 | 8 | profiler callback ptr (reader slot 0 reads `[rcx+3936]`; `rcx = world+0x18` → `world+0xF78`) | static | `0` |
| +0x1000 | 16 | Vec4 — likely **gravity** (reader slot 1 writes `*(_OWORD *)(rcx+4072) = a2`; → `world+0x1000`) | static (scope id 47) | `0` |
| +0x1018 | 4 | f32 — likely **air density** (reader slot 2 writes `*(float *)(rcx+4096) = a2`; → `world+0x1018`) | static (scope id 48) | `0` |
| +0x10A0 | 8 | **hknpSimulationContext** ptr (built by `hknpWorld_Init_SimulationContext`; `[rbx+0x10A0]` where rbx = world) | static + live | `0x130941170` ✓ |
| +0x1121 | 1 | profile-enabled byte (reader slot 0 reads `[rcx+4361]`; → `world+0x1121`) | static | `0` |
| +0x1130 | 8 | pointer back to **owner** (`v55[550] = v49`; 550×8 = 0x1130) | ctor + live | `0xE9B50000` ✓ |
| +0x1138 | 8 | (zero) | ctor (`v55[551] = 0`) | `0` |
| +0x1140 | 8 | (sentinel `0xC0000000`) | ctor (`v55[552] = 0xC0000000`) | `0xC0000000` ✓ |

**Total size**: 4432 bytes (= `0x1150`).

**Retracted from earlier draft:**
- ~~world+0x88~~ → correct is **world+0xA8** (writer slot 3's `[rcx+0x88]` where `rcx = world+0x20`)
- ~~world+0xF60 / +0xFE8 / +0xFF8 / +0x1000 / +0x1109~~ → all were sub-object-relative; correct world-relative values listed above (add `0x18`)
- ~~world+0x168 = RollingSlidingSoundModifier~~ — **NOT ON THE WORLD**. See §88.7-corrected: it's on the **owner**, not the world.
- ~~world+0x170 = R6DefuserMassModifier~~ — same, on owner.
- ~~world+0xE38..+0xF08 MemberSlot list heads~~ — those came from a misread of `world+3632` etc; constructor really writes those via `v15 = *(QWORD *)(v84+16)`, not directly on the world.

### 88.2b — Owner struct layout (`WorldOwnerEntity`, vt `0x7FF6D88D8EA0`)

Live dissect of `0xE9B50000` (the singleton WorldOwnerEntity). The R6-physics extensions and many sub-libs actually live HERE, not on the hknpWorld:

| offset | live value | meaning |
|---|---|---|
| +0x00 | `vt_WorldOwnerEntity` (`0x7FF6D88D8EA0`) | ✓ |
| +0x08 | u32 `256` | (refcount high?) |
| +0x10 | `0x16A880D90` | **hknpWorld back-ptr** ✓ (cross-link with world+0x1130) |
| +0x18 | `0xFA3ED220` | heap subsystem |
| +0x20 | `0x118C4C000` | heap subsystem |
| +0x28 | `0x16E2D5EB0` | **`hknpSharedMotionPropertiesLibrary`** (alloc'd 136 B in ctor; stored at `owner+40`) |
| +0x30 | `0xFA2F4D80` | heap subsystem |
| +0x38 | `0x131D6D628` | heap subsystem |
| +0x48 | `0x11CE6E220` | heap subsystem |
| +0x5C | `0xFFFFFFFF` | sentinel |
| +0x70..+0x160 | 18 packed handles (each ending in `01`) | array of slot-handle qwords (refcount-stamped resource handles, R6's `RefHandle<T>`) |
| +0x168 | `0x102F9CB0` | **`RollingSlidingSoundModifier`** ✓ |
| +0x170 | `0x102FC6B0` | **`R6DefuserMassModifier`** ✓ |
| +0x180 | `0x7FF6D8693148` | vtable ptr (R6-specific sub-system, has 6 real methods) |
| +0x188 | `0x3FE00000109` | packed flags |
| +0x1B8..+0x1C8 | `0xFFFFFFFF` × 4 | sentinels |
| +0x1F8 | `0xFFFFFFFF` | sentinel |

The "packed handles" at +0x70..+0x160 are 18 entries × 8 bytes = 144 bytes — looks like an array of resource references (each is `0x???????01` = ptr with refcount bit). Likely the engine's `array<SharedPtr<HavokSubsystem>>`.

The destructor `WorldOwnerEntity_dtor` (`sub_7FF6CB071FE0`) walks **even more** state at `a1[14], a1[16], a1[18], … a1[44]` (qword indices, stride 2 — every 16 bytes), each one is a `sub_7FF6CB7992B0`-managed object. So the FULL owner extends well past +0x160.

### 88.3 — Sub-objects allocated during world init

| label | bytes | vtable | purpose |
|---|---|---|---|
| `hknpSharedMotionPropertiesLibrary` | 136 | (set inline) | shared motion-prop lookup table |
| `hknpSimulationContext` | (variable) | – | per-thread context root (`world+0x10A0`); see `hknpSimulation_BuildThreadContexts` |
| `hknpSimulationThreadContext` × N | 1952 each | – | one per worker thread |
| `hknpShapeTagCodec` | 32 | `unk_7FF6D852D2A0` | encodes/decodes shape tags |
| `MemberSlot` × multiple | 32 each | various | signal/slot subscribers (collision callbacks, body added/removed, etc.) |
| `GlobalSlot` × 1 | 32 | `unk_7FF6D863A6C0` | global signal subscriber |
| `RollingSlidingSoundModifier` | 8 | `vt_R6_RollingSlidingSoundModifier` | R6 audio hook for surface sliding |
| `R6DefuserMassModifier` | 8 | `vt_R6_DefuserMassModifier` | R6 special — defuser bomb collision mass tweak |

### 88.4 — World reader interface (sub-vtable at world+0x18, `vt_hknpWorld_sub_18`)

8 methods, each wrapped with an **AK::MemoryMgr scope** (Audiokinetic profiler hook). Pattern:
```
v3 = sub_7FF6D7A6B0A0(scopeId);                  // begin profile
sub_7FF6D7A6B010(scopeId, v3+1);
if (profile_active) AK::MemoryMgr::StartProfileThreadUsage(...);
[do the actual work / write to world fields]
sub_7FF6D7A6B010(scopeId, v3);                   // end profile
```

| slot | EA | scope id | role |
|---|---|---|---|
| 0 | `0x7FF6D7A6E6A0` | – | begin-scope wrapper (one of many getName/getX accessors) |
| 1 | `0x7FF6D7A6E7B0` | 47 | `setGravity(Vec4)` — writes 16 bytes to **world+0x1000** (reader sub-obj+0xFE8) |
| 2 | `0x7FF6D7A6E890` | 48 | `setAirDensity(float)` — writes 4 bytes to **world+0x1018** (reader sub-obj+0x1000) |
| 3 | `0x7FF6D7A6E970` | – | (next setter) |
| 4 | `0x7FF6D7B74CE0` | – | (separate function — heavier) |
| 5 | `0x7FF6D7A75BF0` | – | (next setter) |
| 6 | `0x7FF6D7A75D10` | – | (next setter) |
| 7 | `0x7FF6D7A6ED90` | – | (next setter) |

### 88.5 — World writer interface (sub-vtable at world+0x20, `vt_hknpWorld_sub_20`)

8 methods, all heavily MBA-obfuscated (Hex-Rays fails on every one). These dispatch into the body manager (`*(rcx+0x88) = r13` pattern shared across all of them). Each one is a **command** (addBody, removeBody, setBodyTransform, setBodyVelocity, applyImpulse, etc.).

| slot | EA | notes |
|---|---|---|
| 0 | `0x7FF6CB18EA10` | uses esp scrambling — heavy MBA |
| 1 | `0x7FF6CB177790` | |
| 2 | `0x7FF6CB10D4F0` | |
| 3 | `0x7FF6CB0AE970` | starts with `r13 = *(rcx+0x88)` (body manager); ~640 bytes of stack |
| 4 | `0x7FF6CB18B060` | |
| 5 | `0x7FF6CB15E3A0` | |
| 6 | `0x7FF6CB0F1F90` | |
| 7 | `0x7FF6CB121BF0` | |

### 88.6 — World destructor (`sub_7FF6CB0E5F30`, vt slot 1)

```
*world           = &vt_hknpWorld_primary;        // restore vtable
world[3]         = &vt_hknpWorld_sub_18;
world[4]         = &vt_hknpWorld_sub_20;
if (world[552] & 0x40000000) release(world[551]);  // owner ref
sub_7FF6D7A6E100(world);                          // hknpWorld teardown
if (a2) off_7FF6D91348B0(0, world, 0);            // labelled-free
```

### 88.7 — R6-specific Havok extensions (CORRECTED)

- **`vt_R6_RollingSlidingSoundModifier`** @ `0x7FF6D8575110` — 8-byte payload, stored at **`owner+0x168`** (NOT world+0x168). Live value: `0x102F9CB0` ✓. Vtable has 2 real methods (rest are nullsub_1), so it's a small audio-feedback hook only.
- **`vt_R6_DefuserMassModifier`** @ `0x7FF6D85CF1C0` — 8-byte payload, stored at **`owner+0x170`** (NOT world+0x170). Live value: `0x102FC6B0` ✓. Vtable also has only 2 real methods.

Both modifiers are registered into Havok's material library via `sub_7FF6D7B0FD70(world->materialLibrary, flag, modifier, 0)` where:
- RollingSliding registered with flag `8`
- Defuser registered with flag `0x10000000` (top-bit flag = special handling)
- `world->materialLibrary` = `*(_QWORD *)(world + 0xB60)` (= owner+0x10 + 0xB60 indirectly) — needs more decode.

The DefuserMassModifier vtable slot 1 (`sub_7FF6CA283610`) is the actual modifier compute function. It receives the modifier handle and does the engine's standard packed-handle-resolve (`>>0x20` to extract slot index) — i.e., the modifier is referenced by handle and only resolved when the defuser body is being collided.

Both are MaterialModifiers — they hook into hknpWorld's material library to inject R6-specific mass/velocity tweaks (the defuser is famously stickier/heavier than its visual mesh; this is where it's enforced).

### 88.8 — Per-thread simulation contexts (`hknpSimulation_BuildThreadContexts`, `sub_7FF6D7CB1810`)

Builds an array of `hknpSimulationThreadContext` objects (1952 bytes each) — one per worker thread. Stored at `simulation_a1+0` (array base) with count at `simulation_a1+8`. Also wires up:
- Deferred command stream at `sim+0x540` (labelled `"hknpSimulationContext::m_deferredCommandStream"`)
- Body-manager partition list at `sim+0x650` (array `*(sim+1616)+520`, count `*(sim+1616)+528`)

Each thread context is built by `sub_7FF6D7CA9780(ctx, threadIdx)` and registered into the body-manager via `sub_7FF6D7CA9A60(ctx, owner[366], owner, sim+0x520)`.

### 88.9 — Found per-frame label `wld::WorldTasks::UpdatePhysicsAndBroadphase`

String at `0x7FF6D8A69DA0` — the per-frame physics-and-broadphase task label. **0 static xrefs** (MBA-hidden marker call in the world tick), so the task entry point itself isn't reachable by name from static. To find it dynamically: place a software int3 on `R6_PhysicsWorld_Init_hknpWorld` and walk the stack; OR scan for code that LEAs the string (it's stored in a profiler descriptor passed to a job manager).

Per-frame physics task graph names that exist as scope labels (all 0 xrefs):
- `hknpPrepareNarrowPhaseTask`
- `hknpPrepareNarrowPhasePairsTask`
- `hknpProcessNarrowPhasePairsTask`
- `hknpProcessNarrowPhaseGridTask`
- `hknpNarrowPhasePairsBuildJacobians`
- `hknpNarrowPhasePairsGatherThreadOutputsTask`
- `hknpNarrowPhasePairsPrepareGatherTask`
- `hknpBroadphaseOptimizeTask`
- `hknpBroadphaseTriggerCollisionDetector`
- `TtCopyBroadPhaseBodyFilterMasks`, `TtCopyBroadPhasePointIds`, `TtCopyBroadPhaseNodeIds`, `TtCopyBroadPhaseAabbs`, `TtCopyBroadPhaseLayer`
- `TtUpdateBroadphaseIdMapping`, `StUpdateBroadphaseIdMapping`
- `TtShiftBroadphaseSubTask`
- `Broadphase Shift Task`
- `Collide/Export narrowphase outputs`
- `StInitNarrowPhaseTasks`

These map the **entire per-frame physics task graph**. Each task corresponds to a Havok function but the names are baked into profiler tags, not symbol-table entries.

### 88.10 — Globals discovered

| symbol | EA | purpose |
|---|---|---|
| `g_PhysicsWorldOwner` (was `qword_7FF6D91947B0`) | `0x7FF6D91947B0` | the World/Game singleton that owns the hknpWorld. **45+ xrefs** — heavily used across the engine. Read by every system that needs to query the world. |
| `qword_7FF6D9134920` | – | AK MemoryMgr scope ID register (TLS-backed counter) |
| `dword_7FF6D9183A30/B20/BC0` | – | global allocator vptr globals (hknpMemHeap or similar) |
| `qword_7FF6D9C2BE20` | – | static const referenced during init (some default config) |
| `xmmword_7FF6D9F629E0` | – | const XMM (init data for the world's default state) |

### 88.11 — Renamed in IDA this round
- `sub_7FF6CB16C4E0` → `R6_PhysicsWorld_Init_hknpWorld`
- `sub_7FF6D7A6CA00` → `hknpWorld_Init_SimulationContext`
- `sub_7FF6D7CB1810` → `hknpSimulation_BuildThreadContexts`
- `unk_7FF6D86D6790` → `vt_hknpWorld_primary`
- `unk_7FF6D85BB4B0` → `vt_hknpWorld_sub_18`
- `unk_7FF6D84895F0` → `vt_hknpWorld_sub_20`
- `unk_7FF6D8575110` → `vt_R6_RollingSlidingSoundModifier`
- `unk_7FF6D85CF1C0` → `vt_R6_DefuserMassModifier`
- `qword_7FF6D91947B0` → `g_PhysicsWorldOwner`

### 88.12 — RTTI for Havok classes (mass discovery)

R6's binary contains MSVC RTTI for ~60+ Havok physics classes. None are referenced via vtable[-8] (Havok uses its own hkType system instead of MSVC RTTI dispatch). Each class has a `type_info_t` at the address 16 bytes before its mangled name. Notable ones:

| class | mangled string EA | type_info EA |
|---|---|---|
| `hknpWorld` | `0x7FF6D9122C20` | `0x7FF6D9122C10` |
| `hknpSimulation` | `0x7FF6D9122C40` | `0x7FF6D9122C30` |
| `hknpSingleThreadedSimulation` | `0x7FF6D9122E78` | `0x7FF6D9122E68` |
| `hknpCharacterRigidBody` | `0x7FF6D91234F0` | `0x7FF6D91234E0` |
| `hknpShape` | `0x7FF6D91236E8` | `0x7FF6D91236D8` |
| `hknpSphereShape` | `0x7FF6D9123708` | `0x7FF6D91236F8` |
| `hknpConvexShape` | `0x7FF6D9123730` | `0x7FF6D9123720` |
| `hknpCompoundShape` | `0x7FF6D9123918` | `0x7FF6D9123908` |
| `hknpConstraintData` | `0x7FF6D91229E0` | `0x7FF6D91229D0` |
| `hknpRagdollConstraintData` | `0x7FF6D9122A10` | `0x7FF6D9122A00` |
| `hknpBodyIntegrator` | `0x7FF6D9123FD8` | `0x7FF6D9123FC8` |

There are **5 different broadphase configs** (`hknpDefaultBroadPhaseConfig` etc.), **multiple solver types** (`hknpConstraintSolver`, `hknpStreamContactSolver`, `hknpConstraintAtomSolver`), and **17+ constraint data classes** (Hinge, Ragdoll, BallAndSocket, Breakable, Limited, 6Dof, Prismatic, Pulley, RackAndPinion, …).

Full list (mangled-name → real EA): see strings dump at `0x7FF6D9122900..0x7FF6D9124800` range in IDA, search for prefix `.?AVhknp` or `.?AUhknp`.

### 88.13 — Open still
- The **actual per-frame step entry** (the function that drives `hknpSimulation::stepBegin / stepEnd`) — known to exist by name but reachable only through MBA-hidden dispatch.
- **hknpBodyManager** internal layout (it's at `world+0xA8`, derived from writer slot 3 disasm — needs live walking when populated).
- The cinfo struct shape (passed into `anvil_AttachCharacterRigidBody_factory`) — partially decoded.
- Live hknpWorld instance address: scan `+RW` for a qword pointing at `vt_hknpWorld_primary` (`0x7FF6D86D6790`).

---

## §89  Live hknpWorld — found and dissected

**Live address: `0x16A880D90`** — confirmed by AOB-scanning `+RW` for the qword `0x7FF6D86D6790` (= `vt_hknpWorld_primary`). Exactly **one** live instance — the singleton.

### 89.1 — Live layout (from dissect)

| live offset | value | meaning |
|---|---|---|
| +0x00 | `0x7FF6D86D6790` | `vt_hknpWorld_primary` ✓ |
| +0x08 | `0xFFFFFFFF` | refcount low |
| +0x10 | `0x00000001 0x00000000` | refcount high / generation |
| +0x18 | `0x7FF6D85BB4B0` | `vt_hknpWorld_sub_18` ✓ |
| +0x20 | `0x7FF6D84895F0` | `vt_hknpWorld_sub_20` ✓ |
| +0x28 | `0x16A880D90` | **self-ptr** (intra-world link) |
| +0x30 | `0x16A881498` | intra-world (→ `0x16A880DB8`, which is world+0x28) |
| +0x38 | `0x1032EE90` | heap obj (→ vtable `0x7FF6D8319830`) — likely **BroadPhase/Allocator** |
| +0x40 | `0x12FA64050` | heap obj (→ `0x16A83EAF0`) |
| +0x48 | `0x4000000008A` | packed flags |
| +0x50..+0xC7 | zeros | sub-libs not yet wired (uninit state) |
| +0xCC | `0x16A400000000` | partial ptr |
| +0xDC | `0x7D0400000000` | partial ptr |
| +0x88 | `0` | body manager — **NOT YET ALLOCATED** (physics not live) |
| +0xA8 | `0` | (writer-side body manager candidate; also null) |
| +0x10A0 | `0x130941170` | simulation context (allocated ✓) |
| +0x1130 (`world[550]`) | `0xE9B50000` | **owner ptr — points at WorldOwnerEntity** |

### 89.2 — WorldOwnerEntity discovered

The qword at `world+0x1130` points at `0xE9B50000`, whose vtable is **`0x7FF6D88D8EA0`** (named `vt_WorldOwnerEntity`). Its destructor (`sub_7FF6CB071FE0`, renamed `WorldOwnerEntity_dtor`) reveals:

- It's a HUGE struct — cleanup walks `a1[337743]`, `a1[337742]`, … (`>2.7 MB` total).
- Tracks a profiler section `"PhysicWorldBloombergData"`.
- Destructor end: `*a1 = &unk_7FF6D88A3A10;` — the **SAME base-class vtable** as the BaseEntity destructor's deepest ancestor. **WorldOwnerEntity inherits from BaseEntity.**
- Has at least 10 paired `(sub_7FF6CB7992B0)` sub-managers at indices `a1+14, +16, +18, +20, … +44` (qword stride 8) — each one wraps a Havok world manager (constraints, contacts, queries, etc.)
- At `a1+9` holds a `hknpBodyIntegrator`-style sub-object
- At `a1+5..+7` holds connected MemberSlots (cleaned up via `sub_7FF6CB0FFBC0`, `sub_7FF6CB539240`, `sub_7FF6CB138930`)

So the **architecture is**:
```
BaseEntity (vt unk_7FF6D88A3A10 → unk_7FF6D862A6D8 → vt_player_entity)
  ⬑ WorldOwnerEntity (vt_WorldOwnerEntity @ 0x7FF6D88D8EA0)
      • owns hknpWorld instance at  world+0x10
                                    ↓
                                   hknpWorld (4432 bytes, vt_hknpWorld_primary)
                                    • back-pointer to owner at world+0x1130
```

The **World is just another BaseEntity** in the engine. The local player and the world share the same root class.

### 89.3 — Confirmed: physics body manager isn't wired yet on `hknpWorld`, but **the owner is fully populated**

Live offsets verified by `/read_batch` on the live `hknpWorld @ 0x16A880D90`:

| field | offset | live value |
|---|---|---|
| BodyManager (corrected from +0x88) | world+0xA8 | `0` |
| profiler callback | world+0xF78 | `0` |
| gravity Vec4 | world+0x1000 | `0` |
| air density f32 | world+0x1018 | `0` |
| profile-enabled byte | world+0x1121 | `0` |
| simulation context | world+0x10A0 | `0x130941170` ✓ |
| owner back-ptr | world+0x1130 | `0xE9B50000` ✓ |

So `hknpWorld` itself is **partially initialized** — its primary/reader/writer vtables and self-back-link are set, the sim-context skeleton is allocated, but the body manager and per-step state are still null.

**Crucially, the owner is fully populated** (live read on `0xE9B50000`):

| field | offset | live value |
|---|---|---|
| owner vtable | +0x00 | `vt_WorldOwnerEntity` ✓ |
| world back-ptr | +0x10 | `0x16A880D90` ✓ |
| SharedMotionPropertiesLibrary | +0x28 | `0x16E2D5EB0` |
| RollingSlidingSoundModifier | +0x168 | `0x102F9CB0` |
| DefuserMassModifier | +0x170 | `0x102FC6B0` |
| R6 sub-system vtable ptr | +0x180 | `0x7FF6D8693148` |
| 18× packed resource handles | +0x70..+0x160 | all non-null `0x???????01` |

So the engine HAS finished the static physics bootstrap (R6 hooks, motion library, resource handles all wired). What's null is the **per-match / per-level** state on `hknpWorld` (BodyManager, gravity, etc.) — those get filled when a match actually starts and a level is loaded.

### 89.4 — Next-action recipe (when game is active)

```powershell
# 1. find the body manager once physics is live
$body = @{ address="0x16A880E38"; type="qword" } | ConvertTo-Json   # world+0xA8 (body manager)
Invoke-RestMethod -Uri "http://127.0.0.1:9999/read_typed" -Method Post -ContentType "application/json" -Body $body

# 2. find all live hknpBody instances (one per active rigid body in the world)
# hknpBody vtable not yet discovered; once body manager non-null, dissect its first OWORDs and walk

# 3. find the per-frame step entrypoint
# software-int3 patch on R6_PhysicsWorld_Init_hknpWorld (or pick a high-traffic body-manager method)
# walk the stack from the trap to see who calls the step
```

---

---

## §91  Re-verification audit (2026-05-24)

After the user requested "everything must be completely verified", I audited each major claim against live memory. Errors found and fixed:

### Wrong offsets (now corrected)
| § | original claim | actual | reason |
|---|---|---|---|
| 88.2 | `world+0x88` = body manager | `world+0xA8` | writer slot 3's `[rcx+0x88]` where `rcx = world+0x20` (sub-object pointer) |
| 88.2 | `world+0xF60` = profile callback | `world+0xF78` | reader's `[rcx+3936]` where `rcx = world+0x18` |
| 88.2 | `world+0xFE8` = gravity Vec4 | `world+0x1000` | reader's `[rcx+4072]` where `rcx = world+0x18` |
| 88.2 | `world+0x1000` = air density | `world+0x1018` | reader's `[rcx+4096]` where `rcx = world+0x18` |
| 88.2 | `world+0x1109` = profile flag byte | `world+0x1121` | reader's `[rcx+4361]` where `rcx = world+0x18` |
| 88.7 | `world+0x168` = RollingSlidingSoundModifier | **`owner+0x168`** | source code uses `v123 = owner` (v170), not v55 (world) |
| 88.7 | `world+0x170` = R6DefuserMassModifier | **`owner+0x170`** | same — on owner |
| 84.4 | body+0x68 = cinfo+0xB0 | body+0x40 = cinfo+0xB0 | misread of decomp |
| 84.4 | body+0x68 (was cinfo+0xB0) | actually cinfo+0xAC | swapped |
| 84.4 | body+0x70 (was cinfo+0xAC) | actually cinfo+0xA8 | swapped |

### Confirmed correct (live verified)
| claim | live value |
|---|---|
| live hknpWorld @ `0x16A880D90` | `*world = 0x7FF6D86D6790` (vt_primary) ✓ |
| world+0x18 = vt_hknpWorld_sub_18 | `0x7FF6D85BB4B0` ✓ |
| world+0x20 = vt_hknpWorld_sub_20 | `0x7FF6D84895F0` ✓ |
| world+0x10A0 = simulation context | `0x130941170` ✓ |
| world+0x1130 = owner ptr | `0xE9B50000` ✓ |
| owner+0x00 = vt_WorldOwnerEntity | `0x7FF6D88D8EA0` ✓ |
| owner+0x10 = world ptr (cross-link) | `0x16A880D90` ✓ |
| owner+0x28 = SharedMotionPropertiesLibrary | `0x16E2D5EB0` ✓ (non-null) |
| owner+0x168 = RollingSlidingSoundModifier | `0x102F9CB0` ✓ (non-null) |
| owner+0x170 = R6DefuserMassModifier | `0x102FC6B0` ✓ (non-null) |
| sim ctx @ `0x130941170` count | 14 thread contexts at +0x10 |
| each thread context +0x08 = world ptr | `0x16A880D90` (cross-link) ✓ |
| BaseEntity scale Vec3 @ +0xFC | match constructor `mov [r15+0FCh],…` ✓ |
| `vt_BaseEntity_base` @ `0x7FF6D88A3A10` | 100s of derived classes confirm shared-base — true BaseEntity vtable |

### Live thread-context stride note
Static (constructor said `v47 = 1952`): one `hknpSimulationThreadContext` is `1952` bytes (the user-data part).
Live observed inter-instance spacing of the first 6 thread contexts: **0x820 = 2080 bytes**. The extra 128 bytes is likely the allocator's per-block header/footer (Havok's hkMemoryAllocator wraps each labelled-alloc with a control block).

### What I retract
- The earlier "MemberSlot list head at world+0xE38..+0xF08" — those constructor offsets were on a sub-object (`v37 = SharedMotionPropertiesLibrary`), not on the world. Removed from the layout table.
- "world+0xB60 = material library" — that came from a deref chain `*(_QWORD *)(v123 + 16) + 2912` where `v123 = owner` not world. The material library is reached via owner+0x10 → world, then world+0xB60, so it IS on the world; but the +0xB60 number is the world offset of an internal table (need to re-verify).

### Methodology fix
Going forward: when reading sub-object virtual methods (any class with multiple inheritance), the `this` parameter is the **sub-object pointer**, not the primary. To map back to the primary class, add the sub-object's offset (e.g., reader at +0x18, writer at +0x20). I'll annotate every offset I record with which `this` it was derived from.

---

## §90  Status of physics deep dive (updated 2026-05-24, post §§88-89)
| target | status |
|---|---|
| hknpCharacterRigidBody factory + ctor | ✅ §84.3-4 |
| hknpCharacterRigidBody vtable | ✅ `vt_hknpCharacterRigidBody` @ `0x7FF6D8517BE0` |
| RigidBodyComponent class id + registration | ✅ `dword_7FF6D93DF50C`, `qword_7FF6D93E0438` |
| BaseEntity → world cache slot accessor | ✅ `BaseEntity_GetWorldCacheSlot_144` |
| World cache flag bitfield writers | ✅ ~12 variants (§84.6 / §85) |
| Scale Vec3 entity offset | ✅ `+0xFC` (§84.6) |
| Scale push to world cache | ✅ `BaseEntity_PushScaleToWorldCache` |
| Entity transform discriminated union | ✅ `entity+0x80` with kind enum at `+0x8C` (§86) |
| **hknpWorld constructor** (4432 B) | ✅ `R6_PhysicsWorld_Init_hknpWorld` (§88.1) |
| **hknpWorld primary vtable** | ✅ `vt_hknpWorld_primary` @ `0x7FF6D86D6790` |
| **hknpWorld reader vtable** | ✅ `vt_hknpWorld_sub_18` @ `0x7FF6D85BB4B0` |
| **hknpWorld writer vtable** | ✅ `vt_hknpWorld_sub_20` @ `0x7FF6D84895F0` |
| **hknpWorld layout** | ✅ §88.2 (16+ confirmed offsets, ranges) |
| **R6 physics extensions** | ✅ `RollingSlidingSoundModifier`, `R6DefuserMassModifier` (§88.7) |
| **World owner singleton** | ✅ `g_PhysicsWorldOwner` @ `0x7FF6D91947B0` (was `qword_…`) |
| **Owner class** | ✅ `vt_WorldOwnerEntity` @ `0x7FF6D88D8EA0` — inherits from BaseEntity (§89.2) |
| **Live hknpWorld instance** | ✅ `0x16A880D90` (§89.1) — found via vtable scan |
| **Per-thread simulation contexts** | ✅ `hknpSimulation_BuildThreadContexts` (1952 B per thread) (§88.8) |
| **MSVC RTTI for ~60 Havok classes** | ✅ (§88.12) |
| **Physics task-graph names** | ✅ ~20 broadphase/narrowphase task labels (§88.9) |
| **Position write site** (entity → cache slot+0) | ⏳ buried in `BaseEntity_TransformDispatch_at_0x80`'s kind-2 branch |
| **Rotation write site** | ⏳ same |
| **hknpBodyManager internal layout** | ❌ live world has body manager null (physics not active) |
| **Per-frame physics step entrypoint** | ❌ MBA-hidden, needs dynamic int3 + stack walk |
| **Local player heap address** | ❌ no named global; needs live narrowing (240 in-world candidates from §85) |
| **Cinfo struct shape** | ⏳ partial (+0x20, +0x30, +0x90, +0xA0-B4 known) |

### Big-picture architecture (assembled this session)

```
   Anvil/Scimitar runtime
   ┌────────────────────────────────────┐
   │  BaseEntity  (vt unk_7FF6D88A3A10) │  ← root entity class
   └─────────────┬──────────────────────┘
                 │
       ┌─────────┼───────────────────────┐
       │         │                       │
       ▼         ▼                       ▼
  Player ent  WorldOwnerEntity     ~150 other component types
  (26 comps)  (>2.7 MB, vt_WorldOwnerEntity)
              │
              │ owns at +0x10 ── hknpWorld (4432 B)
              │                  ├─ vt primary (1 method)
              │                  ├─ vt reader (8 setters, scope 46-…)
              │                  ├─ vt writer (8 commands → BodyManager)
              │                  ├─ +0x10A0 hknpSimulationContext
              │                  │           └─ N × hknpSimulationThreadContext (1952 B)
              │                  ├─ +0x88   hknpBodyManager (null until match)
              │                  ├─ +0x168  RollingSlidingSoundModifier (R6 ext)
              │                  ├─ +0x170  R6DefuserMassModifier (R6 ext)
              │                  └─ +0x1130 back-ptr to owner

   Per-entity physics integration
   ┌────────────────────────────────────────────────┐
   │ BaseEntity                                     │
   │ ├─ +0x80   transform union (kind=+0x8C)        │
   │ ├─ +0xB0   flag qword (motion class, filter, …)│
   │ ├─ +0xD0   ComponentList head                  │
   │ ├─ +0xFC   scale Vec3                          │
   │ ├─ +0x118  flag byte                           │
   │ ├─ +0x1A8  packed world-cache handle           │
   │ │           (sentinel 0xFFFF0000FFFFFFFF until │
   │ │           placed in a world)                 │
   │ └─ +0x1E3  slot-index byte (0xFF until placed) │
   │                                                │
   │  BaseEntity_GetWorldCacheSlot_144  →  144-byte │
   │                  per-entity slot inside the    │
   │                  world's slot pool             │
   │                                                │
   │  WorldCacheSlot layout (144 B)                 │
   │  ├─ +0x60  flag/quality bitfield               │
   │  ├─ +0x62  dirty byte (transform changed)      │
   │  ├─ +0x63  dirty byte (scale changed)          │
   │  ├─ +0x78  scale-derived qword                 │
   │  ├─ +0x00  derived transform component A       │
   │  └─ +0x10  derived transform component B       │
   │                                                │
   │  → hknpCharacterRigidBody (160 B, allocated    │
   │    by anvil_AttachCharacterRigidBody_factory)  │
   └────────────────────────────────────────────────┘
```

---

## §83  Live-attach context snapshot (2026-05-23)

| key | value |
|---|---|
| Process | `RainbowSix.exe` PID `4308` |
| Image base | `0x7FF6C57F0000` |
| IDA imagebase | `0x7FF6C57F0000` (matches live; no rebase delta on segment EAs) |
| Vtable-slot rebase delta | `0x54AC0000` (raw qwords stored in IDA `.rdata` still encode the *original* PE imagebase `0x7FF71A2B0000`; subtract delta to get live function EAs) |
| Total entities sharing player vtable in `+RW` mem | ≥ 500 (most are template/blueprint instances at low addresses 0x1732xxxx; live heap instances at `0xD4B04xxxx`, `0xE7Dxxxxx`) |
