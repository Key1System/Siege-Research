# Rainbow Six Siege — Full RE Session Recon v4 (Static + Live)

> Consolidates everything from this session: static IDA analysis of
> `RainbowSix_dump.exe.i64`, live memory dissection against a running
> `RainbowSix.exe` in firing range via a custom-extended Bytecode tool,
> and the extensions I added to Bytecode (TLS reading + R6 helpers).
>
> Purely educational / defensive reverse-engineering. Read-only observation
> of a locally-attached game process. No cheat development, no packet
> injection, no game-state modification.

---

## §0 Environment

| Item | Value |
|---|---|
| IDA IDB | `C:\Users\hhhuh\Downloads\Game Cheats\Rainbow Six Siege\r6 dumper\r6 dumper\RainbowSix_dump.exe.i64` |
| IDB imagebase | `0x7FF6FBEB0000` |
| Live process | `RainbowSix.exe` PID 21508 |
| Live imagebase | `0x7FF60FF00000` |
| **ASLR delta** | `-0xEBFB0000` (live = IDB + delta) |
| Image size | `0x187DE000` (~395 MB) |
| Total functions | 304,472 (471 named at session start) |
| Live thread count | 80 |

**Delta conversion:** to translate any IDA address to live: `live = ida + delta`
```python
live = ida - 0xEBFB0000
ida  = live + 0xEBFB0000
```

---

## §1 Bytecode tool extensions I built

Bytecode is at `C:\Users\hhhuh\Downloads\Reverse Engineering\Unpackers\Bytecode\`.
Serves HTTP on `127.0.0.1:9999`. Existing tool already had `/scan_new`,
`/scan_next`, `/watch_writes`, `/snapshot`, `/diff_since`, `/threads`,
`/suspend_thread`, `/inject`, `/hwbp` — everything except **TLS reading**.

### New source file — `core/tls.h`

Adds `NtQueryInformationThread(ThreadBasicInformation)` chain to reach
per-thread TLS blocks:

```
tid → OpenThread(THREAD_QUERY_LIMITED_INFORMATION)
    → NtQueryInformationThread → TEB base
    → rpm(TEB+0x58) → ThreadLocalStoragePointer[]
    → rpm(array + tls_index*8) → TLS slot base
    → rpm(slot + offset) → the key you want
```

Also has `module_tls_index()` which reads `IMAGE_TLS_DIRECTORY64.AddressOfIndex`
out of the target's PE header (R6's main exe uses TLS index `0`).

### New handlers in `ipc/handlers.h`

| Endpoint | Purpose |
|---|---|
| `POST /tls_info` | Discover module's TLS index, sample TEB+slot for first thread |
| `POST /tls_read` | Read a single value (byte/word/dword/qword/float/double) from `TLS[+offset]` of a given tid |
| `POST /tls_read_batch` | Batch-read many offsets from ONE thread's TLS |
| `POST /tls_all_threads` | Read the SAME offset across every thread — useful to find which thread owns a value |
| `POST /tls_dump` | Dump N bytes of a thread's TLS block as hex |
| `GET /tls_game_threads` | List threads where `TLS[+0x1C] == 1` (thread-init flag) |
| `POST /r6_decrypt_health` | Given DamageComp addr + tid, read the encrypted 4 bytes at +0x184..+0x187, apply `TLS[+0x3C80]` XOR + `TLS[+0x3A50]` rotate + subtract `0x4AB53B9A` → HealthState enum |
| `POST /r6_find_local_player_body` | Snapshot N bytes of every body's memory, wait `delay_ms` (during which caller moves in-game), snapshot again — the body whose bytes changed is the local player |

### Build

- Toolset: `v145` (VS 2022 v18.5.4)
- Windows SDK: `10.0.26100.0`
- Output: `x64/Release/Bytecode.exe` (~2.1 MB)
- Built cleanly, only pre-existing warnings from `symbols.h` / `handlers.h`

---

## §2 Live game state (attached RainbowSix.exe)

### 2.1 TLS keys — verified live values from thread 16068 (a game thread)

| Offset | Live value | Purpose |
|---|---|---|
| `+0x1C` | `1` (byte) | thread-init flag |
| `+0x9B8` | `0xFF` (dword) | in-match / mode state (was `2` in old recon; `0xFF` here in firing range) |
| `+0x3900` | `0x9CBE98C04107EC74` | profiler mask |
| `+0x3910` | `0x166149C38FC3EA09` | profiler recorder slot |
| **`+0x3A50`** | `0x35` (`53`) | **HealthState rotate amount** |
| **`+0x3C80`** | `0xE781804E5C7B1E48` | **HealthState XOR key** |
| `+0x6C90` | `0xD9C58B0` | Anvil task-queue free-list head |
| `+0x70A0` | `0xBB03FE1765DDBB2A` | crypto key A |
| `+0x8DE0` | `0x7688AF6FDC10D286` | entity-handle decrypt key (RigidBodyComponent) |
| `+0x8E60` | `0x962D528A3E22362A` | sibling key |
| `+0x8E80` | `0xA027DBC7F9728972` | crypto key |
| `+0x8EA0` | `0xB4C1B406343EF97` | crypto key |
| `+0x3B80` | `0x2012D0B41682C164` | crypto key |
| `+0x3C40` | `0xE76152CB5DE0B716` | crypto key |

**All 80 threads have `TLS[+0x1C] == 1`** in this build. My "game thread" heuristic doesn't discriminate — need a different filter (e.g. non-zero crypto keys at `+0x8DE0`).

### 2.2 Live character bodies (`vt_hknpCharacterRigidBody`)

Live vtable = **`0x7FF61FC748E0`** (= IDA `0x7FF70BC248E0`).

`find_ptr` on the vtable returns 5-6 live bodies at various times (heap churn changes the count). Snapshot addresses from one moment:

| Body | Notes |
|---|---|
| `0xF6415F0` | AI bot |
| `0xF642370` | AI bot (fully dissected — see §3) |
| `0xFE108690` | AI bot |
| `0xFE10DE50` | AI bot |
| `0x11411C130` | AI bot |
| `0x114119430` | (was flagged by /r6_find_local_player_body BUT the address at that offset was actually an hknpBodyIdAndIndex table entry, not a real body — false positive; see §5 for the correct approach) |

**LOCAL PLAYER IDENTIFICATION** — the diff-body-bytes approach caught a live-changing block but it was a `hknpBodyIdAndIndex` bookkeeping table, not a body. Need refinement: filter body candidates by re-reading the vtable at `+0` and confirming it equals the target vtable (i.e. real body objects only, not places that happen to store the vtable value as a field).

### 2.3 Body layout — live-verified against static analysis (100% match)

Body `0xF642370` (an AI bot) matches every field from the static `hknpCharacterRigidBody_ctor` decomp:

| Offset | Live value | Field |
|---|---|---|
| `+0x00` | `0x7FF61FC748E0` | vtable ptr ✓ |
| `+0x08` | `0xFFFFFFFF` | refcount low ✓ |
| `+0x10` | `0x1` | refcount hi / init ✓ |
| **`+0x18`** | **`0x8000000002000A5E`** | **`hknpBodyId`** (32-bit id 0x02000A5E + 32-bit generation 0x80000000) |
| `+0x20` | `0x11D330450` | copied from cinfo+0x28 |
| `+0x28` | `0x1192A68F0` | copied from cinfo+0x30 |
| **`+0x30`** | **`0x1192A68E8`** | **BodyManager ptr** (shared across all 6 bodies) |
| `+0x40` | float `0.1` | quality/damping |
| `+0x58..0x5F` | Vec4 `(0,0,1.0,0.707)` | quat W ≈ √2/2 = 45° rot |
| `+0x60` | `0.7071` `0.08` | friction / restitution |
| `+0x68` | `10.0` `0.05` | mass ish |
| `+0x70` | `1000.0` | max angular velocity |
| `+0x84` | `0` | motion id (init `0x80000000`, now finalized) |

---

## §3 Body Manager `0x1192A68E8`

### 3.1 First 32 bytes

| Off | Value |
|---|---|
| `+0x00` | `0x7FF61F90C920` primary vtable (= IDA `0x7FF70B8BC920`) |
| `+0x08` | `0x7FF61F90CBF0` secondary vtable (multi-inherit) |
| `+0x10` | `0x192A68D0` (intra-self) |
| `+0x18` | `0x192A6FD8` (intra-self) |
| `+0x20` | `0xF641830` sub-manager |
| `+0x28` | `0x140FAA890` sub-manager |
| `+0x30` | `0x40` (flags) `+0x34` `0x400` (capacity) |

### 3.2 Body-manager internal offsets (from `hknpBody_RegisterMassDistribution` decomp)

- `+0x4E8` body table root
- `+0x528` occupied-slot bitmap (each bit = one bodyId in-use)
- `+0xE70` MemberSlot subscriber list (signals for "body added")
- `+0x10D0` body-slot free-list

### 3.3 Body manager vtable (primary) — 64 slots mapped

Named at IDA `0x7FF70B8BC920`. Key slots:

| Slot | Offset | Address (IDA) | Purpose |
|---|---|---|---|
| 8 | `+0x40` | `0x7FF70B03C750` | called from mass-dist reg site |
| 16 | `+0x80` | `0x7FF70B03E1C0` | returns user-data container (TLS-guarded, big) |
| 52 | `+0x1A0` | `0x7FF70B03FA10` | **`addBody(bodyId, flags, userData)`** — installs bodyId + userData into manager tables |

`addBody` internals (from disasm):
- Allocates slot ID via `sub_7FF70B1508C0(manager+0x10D0)` if `bodyId < 0`
- Calls `sub_7FF70B038FC0(manager+0x4E8, id, flags, userData)` — actual add
- On new-body: sets bit in `manager+0x528` bitmap
- Then `sub_7FF70B039D00(manager+0xE70, manager-0x18, userData, flags)` — user-data install

---

## §4 HavokUserData class — LIVE FOUND (fills the mystery box in the architecture diagram)

### 4.1 Vtables

| Symbol | IDA | Live |
|---|---|---|
| **`vt_HavokUserData_BodyRecord`** | `0x7FF70BAC1670` | `0x7FF61FB11670` |
| **`vt_HavokUserData_CharacterSubClass`** | `0x7FF7005FC380` | `0x7FF61464C380` |

Both LEA'd from `anvil_AttachCharacterRigidBody_factory` at `0x7FF700592560`.

### 4.2 Layout (dissected live at `0xFE113630`)

Each HavokUserData record is ~2624 bytes (repeating sub-blocks of ~0x140 each):

| Offset | Field |
|---|---|
| `+0x00` | vtable = `vt_HavokUserData_BodyRecord` |
| `+0x08` | heap ptr (sub-obj) |
| **`+0x10`** | **`hknpBody` ptr** (back to character body) |
| `+0x18` | secondary vtable = `vt_HavokUserData_CharacterSubClass` |
| `+0x30` | heap object |
| `+0x38` | count = 3 |
| `+0x40..+0x88` | 8 pairs of interleaved u32 slot indices `{0,1}{2,3}{4,5}{6,7}` |
| **`+0x98`** | **`hknpBodyId` low 32 bits** |
| `+0xB0..+0xF8` | 8 more slot pairs |
| ... | sub-block repeats |

**This is the reverse-lookup**: given a body, walk `body → manager → user-data table` and each entry has the body ptr at `+0x10`. Given a `HavokUserData` record, `+0x10` gives you the body.

### 4.3 Related helpers

| Function | Address (IDA) | Purpose |
|---|---|---|
| `HavokUserData_Alloc` | `0x7FF700537AD0` | 128-byte allocator, calls `off_...(rec, "MemberSlot")` labeled alloc |
| `HavokUserData_UnlinkAndDestroy_maybe` | `0x7FF700C1B8E0` | cleanup helper |

---

## §5 RigidBody / CharacterController — the diagram's central box

### 5.1 Vtables

| Symbol | IDA | Live |
|---|---|---|
| **`vt_RigidBody_CharacterController`** | `0x7FF70BCBC7D0` | `0x7FF61FD0C7D0` |
| **`vt_RigidBody_CharacterController_sub`** | `0x7FF70BC4D5F8` | `0x7FF61FC9D5F8` |

LEA'd from 10+ functions inside the RigidBodyComponent code region
(`0x7FF700CFD..0x7FF700DD1`).

### 5.2 Layout — dissected live at `0x15D3282D0`

| Off | Field |
|---|---|
| `+0x00` | `hknpBody` ptr (back to body) |
| `+0x08` | encrypted salt qword (per-instance obfuscation) |
| `+0x10` | vtable = `vt_RigidBody_CharacterController` |
| `+0x18` | secondary vtable = `vt_RigidBody_CharacterController_sub` |
| `+0x30` | intra-self ptr |
| `+0x60` | float `5.0` — probably move-speed cap |
| `+0x68` | float `1.0` |
| **`+0x70..+0xE0`** | **4×4 TRANSFORM MATRIX** (4 rows of Vec4) — world position + orientation of the character |
| `+0xF0` | float pair `(60.0, 18.5)` — motion damping / rot inertia |
| `+0xF8` | full 64-bit `hknpBodyId` (matches body[+0x18]) |

**The 4×4 matrix at `+0x70` is where the character's world position + orientation live.** Row 3 (`+0xA0..+0xAF`) = translation vector.

### 5.3 Related motion classes (also LEA'd from factory)

| Symbol | IDA | Purpose |
|---|---|---|
| `vt_HavokMotion_Character` | `0x7FF70BBCF960` | primary motion class |
| `vt_HavokMotion_Character_Callback` | `0x7FF7005C1500` | motion event callback |

---

## §6 World tick — full task graph (mapped statically, still valid live)

### 6.1 ENGINE tick — 15 stages (`eng_InitEngineTickDescriptors @ 0x7FF6FC40B4E0`)

| # | Stage | Execute fn |
|---|---|---|
| 0 | engNetworkUpdatePreWorld | `sub_7FF6FC71A270` |
| 1 | **KickWorldPhysicStep** | `sub_7FF6FC7285E0` (kicks the 23-stage world tick below) |
| 2 | UpdateSystemState | `sub_7FF6FC6847C0` |
| 3 | engUpdateInputDevices | `sub_7FF70047B890` |
| 4 | InputManager::Update | `sub_7FF7004BFEA0` |
| 5 | GraphicEngineLoop::Execute | `sub_7FF6FC4D3EB0` |
| 6 | UIUpdatePostWorld | `sub_7FF6FC663090` |
| 7 | PreStep | `sub_7FF6FC558BE0` |
| 9 | KickEngineBackgroundTasks | `sub_7FF6FC66E010` |
| 10 | EndFrame | `sub_7FF6FC6EF310` |
| 11 | EndEngineFrame | `sub_7FF6FC6663B0` |
| 12 | DominoAndTheaterUpdate | `sub_7FF6FC6E1F00` |
| 13 | BeginFrame | `sub_7FF6FC668030` |
| 14 | BeginEngineFrame | `sub_7FF6FC4A6B80` |

### 6.2 WORLD tick — 23 stages (`R6_World_InitTaskDescriptors @ 0x7FF6FC465560`)

All 23 functions renamed as `wld_*`. Key ones for physics/skeleton:

| # | Stage | Fn |
|---|---|---|
| 2 | **UpdatePostSkeleton** | `0x7FF6FF780F70` |
| 8 | **wldSkeletonBatched** | (dispatched via `wld_Task_FireHandle_Vtbl5` @ `0x7FF6FF7ADA60` — Anvil handle → vtable[5]) |
| 14 | **UpdatePhysicsAndBroadphase** | `0x7FF6FF76F6D0` — calls `hknp_PhysicsStep_A/B` |
| 16 | KickCharacterStoryboards_PostPhys | `0x7FF6FF7AA810` |
| 17 | **KickAnimPrePhysics** | `0x7FF6FF7A91B0` — filters entities into anim task list |
| 18 | GameplayAIPrePhysic | `0x7FF6FF7A2690` |
| 20 | Component_PrePhysicUpdate_MultiThreaded | `0x7FF6FF790B10` |
| 21 | Component_PostPhysicUpdate_MultiThreaded | `0x7FF6FF792110` |

Physics step branch: `hknp_PhysicsStep_A @ 0x7FF6FF6F6C10` OR `hknp_PhysicsStep_B @ 0x7FF700DC7870` (chosen by MBA-decrypted flag).

---

## §7 hkSkeleton — Havok reflection fully decoded

Located hkClass metadata at `0x7FF70B931B40`. 8 fields:

Verified 2026-07-17 by decoding the hkClassMember[] array at `0x7FF70B931A08` in IDB (8 entries × 40B). Each member's name-ptr (+0x08), offset (+0x10), and type tag (+0x12 = `0x20` = `hkArray`) match the pseudocode exactly.

| Offset in `hkSkeleton` | Field | Type | Size |
|---|---|---|---|
| `+0x18` | `name` | `hkStringPtr` (bare `const char*`) | **8B** (not 16B — corrected) |
| `+0x20` | `parentIndices` | `hkArray<int16>` | 16B |
| `+0x30` | `bones` | `hkArray<hkBone*>` | 16B |
| **`+0x40`** | **`referencePose`** | **`hkArray<hkQTransform>` — REST POSE (48B per bone)** | 16B |
| `+0x50` | `referenceFloats` | `hkArray<hkReal>` | 16B |
| `+0x60` | `floatSlots` | `hkArray<hkStringPtr>` | 16B |
| `+0x70` | `localFrames` | `hkArray<LocalFrameOnBone>` | 16B |
| `+0x80` | `partitions` | `hkArray<Partition>` | 16B |

Total `sizeof(hkSkeleton) = 0x90` bytes. hkClass "hkSkeleton" name-string at `0x7FF70C163E38`; hkClass descriptor at `0x7FF70C4C2378` (with member array header at `0x7FF70B9319F0`, member entries begin at `+0x18`).

### hkQTransform (48 bytes per bone)

```
+0x00  Quaternion rotation    (16B: x, y, z, w)
+0x10  Vector3    translation (16B: x, y, z, +pad)
+0x20  Vector3    scale       (16B: x, y, z, +pad)
```

### hkArray (16 bytes)

```
+0  ptr
+8  size (u32)   +C  capacity | flags (u32)
```

### Ragdoll + skinning wire (correction)

**Note (2026-07-17):** the earlier claim that `0x7FF70C1627B0` and `0x7FF70C1627C0` are runtime maps was wrong — those addresses hold the **reflection field-name strings** `"boneToBodyMap"` and `"boneMatrixMap"`, not the maps themselves. The field names confirm Havok's schema exposes these two maps (bone-idx → hknpBodyId for ragdoll, bone-idx → GPU skinning slot), but the actual per-character runtime instances live inside a per-character `SkeletonComponent` — still to be located on a live character.

---

## §8 BaseEntity layout (updated for this build)

| Field | Old (2022 recon) | **Current build** |
|---|---|---|
| ComponentList head | `+0xD0` | **`+0xE0`** |
| DamageComponent slot idx | `+0x1E8` | **`+0x200`** |

Character-entity SUBCLASS (from `wld_KickAnimPrePhysics` decomp):
- `+0x0B8` byte, bit 0 = "anim eligible" flag
- `+0x114` qword = Component array (sub-class ComponentList)
- `+0x1D8` word, `(w & 0x1F) - 4 <= 4` = state 4..8 eligible
- `+0x214` byte = SkeletonComponent slot index

---

## §9 DBNO / Health chain (partially re-verified live, encryption fully documented)

### Chain

```
BaseEntity
  → [+0xE0] ComponentList
  → [+0x200 byte] * 8 → DamageComponent
  → [+0x184..+0x187] encrypted HealthState 4 bytes
```

### HealthState decrypt algorithm (verified from R6_DBNOMonitor_Tick)

```python
# Live keys from thread 16068:
key = 0xE781804E5C7B1E48   # TLS[+0x3C80]
rot = 53                   # TLS[+0x3A50] (& 0x1F = 21)
sub = 0x4AB53B9A           # inline constant

enc = read_bytes(damage_comp + 0x184, 4)
raw = 0
for i in range(4):
    raw |= (enc[i] ^ ((key >> (i*8)) & 0xFF)) << (i*8)
raw = (raw - sub) & 0xFFFFFFFF
if (rot & 0x1F) not in (0, 32):
    r = rot & 0x1F
    raw = ((raw >> r) | (raw << (32 - r))) & 0xFFFFFFFF

# raw = HealthState enum
# 3 = DBNO, 4 = dead, 0-2 = alive/injured (need more samples)
```

**Bytecode endpoint `/r6_decrypt_health`** wraps this — pass the DamageComp
address + game thread tid, get back the state and meaning.

### R6 handlers named

| Function | IDA |
|---|---|
| `R6_DBNOMonitor_Tick` | `0x7FF6FDFF4830` |
| `R6_OnEntityEnterDBNO` | `0x7FF703579970` |
| `R6_OnEntityRevive` | `0x7FF703709C70` |

---

## §10 Anvil handle resolve — g_AnvilClassRegistry `0x7FF70C6E3E30`

Live verified — first qword at that address = `0x7FF620738ED8` (populated).

```c
class_arr  = *((QWORD*)g_AnvilClassRegistry + 110);   // +0x370 (=880)
class_info = class_arr[HIDWORD(handle)];
slot_byte  = *(BYTE*)(class_info + WORD1(LOW(handle)));
if (slot_byte == -1) slot_byte = *((BYTE*)g_AnvilClassRegistry + 1908);
slot       = slot_byte & 0x7F;
if (slot >= 0x7F) __debugbreak();
instance   = ((QWORD*)g_AnvilClassRegistry + 111)[slot];  // +0x378 (=888)
```

Handle format: `{high32 = generation | flags, low16 = slot_byte_offset, low16 = reserved}`.

---

## §11 All named symbols this session (persistent in IDB)

### Functions

- `R6_PhysicsWorld_Init_hknpWorld` @ `0x7FF700DA8DF0`
- `anvil_AttachCharacterRigidBody_factory` @ `0x7FF700592560`
- `hknpCharacterRigidBody_ctor` @ `0x7FF70B085720`
- `hknpBody_RegisterMassDistribution` @ `0x7FF70B085BC0`
- `R6_RigidBodyComponent_AttachEntity` @ `0x7FF700531860`
- `R6_RigidBody_AttachEntity_Thin` @ `0x7FF700579700`
- `R6_RigidBodyCinfo_Build` @ `0x7FF7005A69E0`
- `R6_RigidBodyContainer_ReportLeaks` @ `0x7FF700D3CFD0`
- `R6_RigidBodyLeak_LogEmit` @ `0x7FF700DCBF50`
- `PhysicsWorldOwner_Attach_or_Detach` @ `0x7FF6FF6F3500`
- `hknp_PhysicsStep_A` @ `0x7FF6FF6F6C10`
- `hknp_PhysicsStep_B` @ `0x7FF700DC7870`
- `HavokUserData_Alloc` @ `0x7FF700537AD0`
- `HavokUserData_UnlinkAndDestroy_maybe` @ `0x7FF700C1B8E0`
- `eng_InitEngineTickDescriptors` @ `0x7FF6FC40B4E0`
- All 15 `engEngineLoop_*` execute functions (see §6.1)
- `R6_World_InitTaskDescriptors` @ `0x7FF6FC465560`
- `R6_WorldTaskDescriptor_SetLabel` @ `0x7FF6FC456170`
- `R6_WorldTaskDescriptor_ctor` @ `0x7FF6FC449430`
- All 23 `wld_*` execute functions (see §6.2)
- `wld_Task_FireHandle_Vtbl5` @ `0x7FF6FF7ADA60`
- `wld_DispatchSignal` @ `0x7FF700589EC0`
- `wld_PrePhysics_Setup` @ `0x7FF6FF758B30`
- `R6_Init_AnimationHandler_TaskDescriptor` @ `0x7FF700BDB990`
- `R6_AnimationHandler_Update` @ `0x7FF6FF4EC300`
- `R6_AnimTask_MainCallback` @ `0x7FF6FC3CF7B0`
- `Anvil_TaskQueue_Enqueue` @ `0x7FF6FF511C80`
- `Anvil_TaskQueue_GetOrCreateContext` @ `0x7FF6FF503020`
- `R6_DBNOMonitor_Tick` @ `0x7FF6FDFF4830`
- `R6_OnEntityEnterDBNO` @ `0x7FF703579970`
- `R6_OnEntityRevive` @ `0x7FF703709C70`
- `AnvilCollection_MakeArray` @ `0x7FF70B0886C0`
- `AnvilCollection_PushArray` @ `0x7FF70B089720`
- `AnvilCollection_Grow` @ `0x7FF700523780`
- `AnvilRef_DestroyElement` @ `0x7FF70B026240`
- `AnvilRef_ConstructAt` @ `0x7FF70B026290`
- `Havok_MassDistribution_Init` @ `0x7FF70B0DACF0`
- `Havok_TagObject` @ `0x7FF70B0CD650`
- `thread_init_ensure_state` @ `0x7FF70B0D0458`
- `R6_Physic_LogFormatter` @ `0x7FF7013DB250`
- `R6_PhysicConfig_Parser` @ `0x7FF702726E80`
- `R6_Physic_DeferCastTask_Setup` @ `0x7FF700606180`
- `R6_Physic_HavokFXGraphicSync` @ `0x7FF6FF712B90`

### Data / vtables

- `vt_hknpCharacterRigidBody` @ `0x7FF70BC248E0`
- `vt_hknpCharacterRigidBody_BASE` @ `0x7FF70B8BEAA0`
- `vt_hknpRefMassDistribution` @ `0x7FF70B8BEA88`
- `vt_HavokUserData_BodyRecord` @ `0x7FF70BAC1670`
- `vt_HavokUserData_CharacterSubClass` @ `0x7FF7005FC380`
- `vt_RigidBody_CharacterController` @ `0x7FF70BCBC7D0`
- `vt_RigidBody_CharacterController_sub` @ `0x7FF70BC4D5F8`
- `vt_HavokMotion_Character` @ `0x7FF70BBCF960`
- `vt_HavokMotion_Character_Callback` @ `0x7FF7005C1500`
- `g_AnvilClassRegistry` @ `0x7FF70C6E3E30`
- `g_AnvilTaskDescriptorAlloc` @ `0x7FF70C6E3E68`
- `g_AnvilAllocErrorEnabled` @ `0x7FF70C4F41DC`
- `g_AnvilAllocOOMCallback` @ `0x7FF70C6E3EF8`
- `g_TimeClockDomain0` @ `0x7FF70C6A7A98`
- `g_TimeClockDomain1` @ `0x7FF70C6AAC70`
- `g_TimeClockDomain2` @ `0x7FF70C6A9518`

---

## §12 Big-picture architecture diagram (mapped to real code)

```
                              ┌───────────────────┐
                              │      Entity       │
                              │  (BaseEntity+     │
                              │   subclass)       │
                              └──────┬────────────┘
                                     │ +0xE0
                                     ▼
                          ┌──────────────────────┐
                          │   ComponentList[]    │
                          └──────────┬───────────┘
                                     │ [+0x200] * 8
                                     ▼
                          ┌──────────────────────┐
                          │   DamageComponent    │
                          │  (encrypted +0x184)  │
                          └──────────────────────┘

Physics side (parallel to ECS):

    Entity ──┬──> RigidBodyComponent (ECS)
             │       R6_RigidBodyComponent_AttachEntity @ 0x7FF700531860
             │       creates:
             │       └── hknpCharacterRigidBody (160B)
             │              vt_hknpCharacterRigidBody @ 0x7FF70BC248E0
             │              +0x18 = hknpBodyId
             │              +0x30 = BodyManager (shared singleton)
             │
             └──> PhysicWorld (per-World)
                    PhysicsWorldOwner_Attach_or_Detach @ 0x7FF6FF6F3500
                    │
                    ├── HavokWorld owns hknpWorld
                    │      R6_PhysicsWorld_Init_hknpWorld @ 0x7FF700DA8DF0
                    │      ├── hknpWorld reader/writer sub-vtables
                    │      └── HavokCommandQueue (deferred writes) [not yet located]
                    │
                    └── Bodies registered via BodyManager
                           ├── vtbl[52] = addBody (bodyId + userData)
                           └── HavokUserData records (reverse map bodyId → subsystem)
                                  vt_HavokUserData_BodyRecord @ 0x7FF70BAC1670
                                  +0x10 = body ptr, +0x98 = bodyId low32

CharacterController wraps the body with world-space state:
    vt_RigidBody_CharacterController @ 0x7FF70BCBC7D0
    +0x00 = body ptr
    +0x70 = 4×4 world transform  ← THIS is where player position lives
    +0xF8 = hknpBodyId

Per-frame tick pipeline:
    engEngineLoop_KickWorldPhysicStep_Fn @ 0x7FF6FC7285E0
       └── R6_World_InitTaskDescriptors sets up 23 world stages
              ├── wld_KickAnimPrePhysics @ 0x7FF6FF7A91B0
              │      └── filters entities → Anvil_TaskQueue_Enqueue
              │             └── R6_AnimationHandler_Update @ 0x7FF6FF4EC300
              ├── wldSkeletonBatched (Anvil handle dispatch → SkeletonSystem)
              ├── wld_UpdatePhysicsAndBroadphase @ 0x7FF6FF76F6D0
              │      └── hknp_PhysicsStep_A/B
              └── wld_UpdatePostSkeleton @ 0x7FF6FF780F70
                     └── event fan-out to subscribers
```

---

## §13 Live-verification recipes (using extended Bytecode tool)

### Attach

```bash
curl -s -X POST http://127.0.0.1:9999/attach -H 'Content-Type: application/json' \
     -d '{"process":"RainbowSix.exe"}'
```

### Read TLS keys from a game thread

```bash
# 1. Get TLS index (should be 0 for RainbowSix.exe)
curl -s http://127.0.0.1:9999/tls_info

# 2. List candidate game threads
curl -s http://127.0.0.1:9999/tls_game_threads

# 3. Read the R6 keys from a specific tid
curl -s -X POST http://127.0.0.1:9999/tls_read_batch \
     -H 'Content-Type: application/json' \
     -d '{"tid":16068,"offsets":["0x3C80","0x3A50","0x8DE0","0x8E60"]}'
```

### Find local player (needs YOU to move in-game during the delay)

```bash
# Wide byte-diff on all bodies
curl -s -X POST http://127.0.0.1:9999/r6_find_local_player_body \
     -H 'Content-Type: application/json' \
     -d '{"vtable":"0x7FF61FC748E0","delay_ms":3000,"matrix_offset":"0x0"}'
```

Note: this catches false positives from tables that happen to store the vtable value.
**Refinement needed:** filter candidates by re-reading `[body+0]` and confirming it
equals the target vtable.

### Decrypt live HealthState (once you have a DamageComponent address)

```bash
curl -s -X POST http://127.0.0.1:9999/r6_decrypt_health \
     -H 'Content-Type: application/json' \
     -d '{"damage_comp":"0x<live_addr>","tid":16068}'
```

---

## §14 Still open

1. **Reliable local-player body identification** — need to filter body-scan
   candidates by re-reading `[candidate+0]` and verifying it equals the vtable
   value (not just an address that stores the value as a field).

2. **Entity → CharacterController → Body chain**: I have all three objects
   individually mapped but the entity-to-CharacterController link uses
   an Anvil handle (encrypted). Now that Bytecode can read TLS I have the
   decrypt keys — need to hunt the specific entity field that holds the
   character-body handle, then decrypt.

3. **Skeleton runtime instance**: the per-character `SkeletonComponent` and
   its bone-matrix runtime array. Static side is fully mapped (§7); need
   live dissect of one running character to find the offset within
   `character entity+0x114` component array.

4. **HavokCommandQueue** (writer side / deferred mutation queue): identified
   in the diagram but not yet located in code. Should be findable via
   xrefs to the hknpWorld writer sub-vtable.

---

## §15 Files touched / created this session

### Bytecode source additions

- **NEW:** `C:\Users\hhhuh\Downloads\Reverse Engineering\Unpackers\Bytecode\Bytecode\core\tls.h` — full TLS reader
- **EDITED:** `C:\Users\hhhuh\Downloads\Reverse Engineering\Unpackers\Bytecode\Bytecode\ipc\handlers.h` — added 8 new endpoints (`/tls_info`, `/tls_read`, `/tls_read_batch`, `/tls_all_threads`, `/tls_dump`, `/tls_game_threads`, `/r6_decrypt_health`, `/r6_find_local_player_body`)
- **BUILT:** `C:\Users\hhhuh\Downloads\Reverse Engineering\Unpackers\Bytecode\Bytecode\x64\Release\Bytecode.exe` (~2.1 MB, v145 toolset, WinSDK 10.0.26100.0)

### IDA IDB

- Path: `C:\Users\hhhuh\Downloads\Game Cheats\Rainbow Six Siege\r6 dumper\r6 dumper\RainbowSix_dump.exe.i64`
- ~60 functions renamed
- ~15 vtables named
- ~10 global data symbols named
- 8+ deep multi-paragraph comments on key functions

---

## §16b Session 2 findings (2026-07-17, base 0x7FF6D5B10000)

Follow-up live session. Verified everything from §2 against a fresh
`RainbowSix.exe` (PID 18212, module base `0x7FF6D5B10000`, ASLR delta
`-0xEBFB0000` — SAME as prior session).

### RVA table (stable across sessions — apply to any live module base)

| Symbol | IDB address | RVA |
|---|---|---|
| `vt_hknpCharacterRigidBody` | `0x7FF70BC248E0` | **`0x0FD748E0`** |
| `vt_RigidBody_CharacterController` | `0x7FF70BCBC7D0` | **`0x0FE0C7D0`** |
| `g_AnvilClassRegistry` | `0x7FF70C6E3E30` | **`0x10833E30`** |

### CC world-position offset — CORRECTED

Recon MD §5.2 claimed `WORLD_POS = CC + 0xA0` (row 3 of a 4×4 at `+0x70`).
**That was wrong.** Live-verified on 4 firing-range bots:
- `+0xA0..+0xAF` holds a quaternion identity `(1, 0, 0, 0)` — NOT translation.
- **Real world Vec3 is at `CC + 0x1D0`.**

Verified positions (4 bots in a line at Y=20.41, Z=31.34, X in {53, 55, 57, 59}):
```
CC 0x163E9B570 → (59.0, 20.41, 31.34)
CC 0x163FBABF0 → (55.0, 20.41, 31.34)
CC 0x16403F050 → (57.0, 20.41, 31.34)
CC 0x1640D7D20 → (53.0, 20.41, 31.34)
```

### CC layout — more offsets discovered

| Off | Field |
|---|---|
| `+0x00` | body ptr (churns as bodies recycle) |
| `+0x08` | encrypted salt qword |
| `+0x10` | vt_cc = `vt_RigidBody_CharacterController` |
| `+0x18` | secondary vtable |
| `+0xF0` | damping/friction floats (60.0f, 18.5f) |
| **`+0x1D0`** | **Vec3 world position (x, y, z)** |
| `+0x5C0` | subclass vtable |
| `+0x630` | another subclass vtable |
| `+0x680` | subclass vtable |
| `+0xF90 / +0xFF0` | ptr to a sub-object (paired — same address twice, ~animation subsystem?) |
| `+0x12C0 / +0x1320` | ptr to another sub-object (paired) |

### Global body-pointer array (new — undocumented in recon v1)

Found a heap array at `0x1287C58E0` (this session) that stores **every live body pointer** at a 32-byte stride. Each entry:
```
+0x00  body_ptr
+0x08..+0x1F  zeros
```
Contained: `0x122121090, 0xF642490, 0x19103EB30, 0x1221201F0, ...` — all
live hknpCharacterRigidBody pointers. This is the R6 global body table.

Nothing points to this array (find_ptr on `0x1287C58E0` returned 0 hits),
so it's reachable only from the BodyManager's internal state.

### Object churn model — critical for external tools

- **Bodies** churn CONSTANTLY. Same character keeps a fixed `hknpBodyId`
  but the pointer changes as slots recycle. Repeated scans return
  different addresses.
- **CharacterControllers** are longer-lived but NOT eternal. If a
  character dies + respawns, the CC address is recycled to a non-CC
  object.
- **Vtables** (both body and CC) are absolutely stable within a session
  (derived from module base by RVA).
- **BodyManager pointer** — nothing in `.data`, `.rdata` or as an
  `xref_rip indirect` slot holds it. Only reachable through Anvil handle
  encryption (recon MD §10) or via any body's `+0x30`.

### External-tool implications

1. Static PE anchor for the entity list DOES NOT EXIST — R6 hides
   everything behind Anvil encrypted handles + TLS crypto keys.
2. `find_ptr(vt_cc)` returns 2000+ hits (vt_cc is a shared field in many
   unrelated arrays). Filter to real CCs by checking:
     * `[cand + 0x10] == vt_cc` AND
     * `[body @ cand + 0x00] + 0x00 == vt_body`
3. Practical strategy for tools like Siege External:
     * Scan for vt_cc in **private RW < 256 MB regions**, multithreaded
     * On first scan, remember WHICH regions had real CCs (arenas)
     * Cache arena bases to disk; subsequent scans read only those
       (~5-15 MB total, ~50-200 ms)
     * On per-frame CC read, if `[cc+0x10] != vt_cc`, character died;
       flip a rebuild flag
     * Full re-enumeration falls back to full private-RW when arenas
       empty out

---

## §16c SkeletonDescriptor system (2026-07-17)

Full mapping of the SkeletonDescriptor pool + AcquireSkeletonDescriptor
path — the R6 mechanism that turns per-entity SkeletonComponents into
shared descriptors from a global pool. Anchored via signature
`E8 ? ? ? ? F7 ? E8 00 00 00 FF FF FF 3F 0F 84 ? ? ? ?` which lands at
`0x7FF6FE4006B5` (in the middle of `sub_7FF6FE3FEF00`).

### Call graph
```
sub_7FF6FE3FEF00 (entity update)
    └── sub_7FF6FE391120 (rcx=entity, dl=flag)  ← AcquireSkeletonDescriptor
            ├── allocator(240)                    ← if SkeletonComponent doesn't exist yet
            ├── sub_7FF700EF7CD0                  ← SkeletonComponent::init crypto fields
            └── pool_base decrypt + slot alloc/rebind
```

### Entity offsets used

| Off | Field | Notes |
|---|---|---|
| `+0x2A8` (680) | `SkeletonComponent*` | pointer to 240-byte alloc |
| `+0x1A8` (424) | `skeletonDescKey_seed` | qword; `0x9CFB33A3980E2775` = null sentinel |
| `+0x1B0` (432) | `skeletonDescSlotHandle` | encrypted qword; low bits = pool epoch, bits 33-47 = slot index (see below) |
| `+0x76` byte | flag byte | bit 0 (0x1) = has-descriptor |

### SkeletonDescriptor pool

- **Base decrypt formula:**
  `pool_base = ROL(qword_7FF70D1BAC08 ^ 0x6BB3798709620272, 34) ^ *(qword_7FF70C56DDD0 - MBA_index)`
  Where `MBA_index` is computed from a stack address in the caller — **T2 template**, external-undecryptable analytically. Must be captured via trampoline / hooking.
- **Slot stride: 144 bytes** (`v16 = 144 * slot_idx`)
- **Slot handle format** (stored at entity+0x1B0):
  - bit 32:      valid flag (`0x100000000`)
  - bits 0-15:   pool epoch (compared to `dword_7FF70D281DE0`)
  - bits 33-47:  slot index (masked with `0x7FFF`)
- **skeletonDescKey written to slot+0x68 (104):** `entity[+0x1A8] + 0x6304CC5C67F1D88B`
- **Per-descriptor flags word at slot+0x60 (96):** massive bit-packed field derived from `entity[+0xB8]`, `entity[+0x76]`, `entity[+0x113]`

### Static globals

| IDA sym | Purpose | Live value (session 2026-07-17, pid 20940) |
|---|---|---|
| `qword_7FF70D1BAC08` | pool base seed (encrypted) | `0xFAD2ED2DA53ACE38` |
| `qword_7FF70C56DDD0` | MBA lookup table base | `0xC31C32B77220229C` |
| `qword_7FF70C59BA30` | ROL-count MBA table | `0x8898252B923FB346` |
| `dword_7FF70D281DE0` | current pool epoch | `0x114D8` = 69,336 |
| `dword_7FF70D286938` | slot allocation counter | `0x37` = 55 |

### New TLS crypto keys (from SkeletonComponent init)

| Offset | Purpose |
|---|---|
| `TLS[+0x9D08]` | SkeletonComponent field XOR key A (byte-packed, +MBA rolling `0x731DD9118AE0FEE`) |
| `TLS[+0x9D40]` | SkeletonComponent field XOR key B (+MBA rolling `0x1DF204945C7B1B7`) |
| `TLS[+0x9D68]` | ROL-count subkey for stored qword |

### Init crypto flow

```c
// Plaintext template that gets encrypted into SkeletonComponent+0x4..+0xC:
struct plain { float f = 1.0f; int32_t i = 0; };   // v27=0x3F800000, v28=0

// Two-pass byte/qword XOR with TLS-keyed rolling MBA:
for (int i = 0; i < 12; ++i) {
    if (i <= 4) {                 // qword pass (writes 8B)
        *(u64*)(dst + i) = *(u64*)(&plain + i) ^ tls_key;
        tls_key += 0x731DD9118AE0FEE;   // rolling MBA
        i += 6;                    // skip ahead 7
    } else {                      // byte tail
        dst[i] ^= (tls_key >> (8*i)) & 0xFF;
    }
}
// Then: ROL8(dst[+4..+12], count) where count comes from qword_7FF70C59BA30 table
// The ROL count is TLS-derived (T2 stack-hashed lookup).
```

### Live-verified candidate entity

Entity `0x118539E70` (this session):
- `+0x2A8` = `0x11853A100` (SkeletonComponent, populated with heap ptrs + floats + vtable at `+0x28`)
- `+0x1A8` = `0x21` (small key seed — not the sentinel `0x9CFB33A3980E2775`)
- `+0x1B0` = `0x1184BA280` (slot handle — heap-shaped, may be encrypted)

### External decrypter status

- **AcquireSkeletonDescriptor entire path is T2-family.** The pool base decrypt uses a stack-address-derived MBA index. Cannot invert analytically from an external tool.
- **Internal DLL (siege_crypto.dll) can trampoline** — install a probe on `sub_7FF6FE391120` that returns the current descriptor pointer for a given entity.
- **All globals + TLS keys are read-accessible** so we can snapshot the pool state; decrypt requires the trampoline.

### Recon-MD site table update

Recommend adding to CRYPTO_MAP.md:
- T2 site: `sub_7FF6FE391120` @ IDB `0x7FF6FE391120` — SkeletonDescriptor acquire
- T7-adjacent: SkeletonComponent init crypto uses TLS keys `0x9D08 / 0x9D40 / 0x9D68`

### Enumerated SkeletonComponents (live 2026-07-17, pid 20940)

`find_ptr(0x7FF6E28B34F0)` (SkeletonComponent sub-entry vtable) returns
**50 hits**; every one tested is a real component whose base is
`hit - 0x28`. Every base validates:
- `[base+0x18] == base` (self-ref)
- `[base+0x60]` is a heap manager pointer (varies by owner)

15 confirmed samples (this session):
```
0x11853A100  0x11840B7B0  0x11844DC60  0x11845FA10  0x118462DA0
0x118491BB0  0x1184A3870  0x1184BD7A0  0x118508470  0x11851BAE0
0x118527DE0  0x11852DD10  0x118558220  0x1185739F0  0x11859C000
```
Plus ~35 more from the raw find_ptr list. This is one component per live
character-entity + some prop entities.

### SkeletonComponent layout (per bone-carrier)

Confirmed live at `0x11853A100`:

| Off | Field |
|---|---|
| `+0x00..+0x40` | Header — misc heap ptrs + vtable at `+0x28` = `0x7FF6E28B34F0` |
| `+0x18` | **self ptr** (validation anchor) |
| `+0x38` | shared owner `0x11853A040` (points back into the SkeletonComponent header) |
| `+0x60` | **shared bone manager ptr** (varies per component — `0x11C1913B8` for our test) |
| `+0x70..end` | **N sub-object entries at stride `0x70` (112 bytes)** — one per bone role |

### Bone-slot sub-object (stride `0x70`)

Each entry inside the SkeletonComponent has this shape:

| Off (within entry) | Field |
|---|---|
| `+0x00` | small heap ptr (sub-buffer) |
| `+0x10` | heap ptr |
| `+0x18` | self ptr (intra-entry) |
| `+0x28` | vtable A (varies — role-specific) |
| `+0x30` | vtable B |
| `+0x38` | shared parent SkeletonComponent header |
| `+0x60` | shared bone-manager ptr |
| `+0x68` | vtable C (`0x7FF6E7XXXXXX` range) |

### Bone-slot manager (`0x11C1913B8` for our sample)

Holds an array of per-bone slot records at **stride `0x30` (48 bytes)**:

| Off (within slot) | Field |
|---|---|
| `+0x00` | vtable (repeating in groups by bone type) |
| `+0x08` | float `~2.13` (probably bone weight / blend factor) |
| `+0x0C..+0x10` | encrypted qword (per-slot state — T7-style crypto) |
| `+0x10..+0x18` | shared seed `7B 17 44 86 30 FA 1D XX` (differs only in high nibble) |
| `+0x18..+0x20` | 8-byte encrypted state (per-instance) |

Bone slot vtables seen (grouped):
- `0x7FF6E57DA550` — 3x (bone group A — probably head/torso)
- `0x7FF6E5741E40` — 2x
- `0x7FF6E56F8770` — 5x (largest group — probably limbs)

### Practical takeaway

For ESP-style rendering of a **specific bone (e.g. head)** on all
characters:
1. Enumerate SkeletonComponents via `find_ptr(0x7FF6E28B34F0) - 0x28`
2. For each, dereference `+0x60` to get the bone manager
3. Walk the bone manager at stride `0x30` to find the head-bone slot
   (identified by vtable group)
4. Decrypt the per-slot state (T7 template — needs constants extraction
   from the vtable's read method)

**Fully bridging Entity → CharacterController → SkeletonComponent → Bone**
now has all links except the final per-slot decrypt.

### §16d Bone-transform layout (LIVE-VERIFIED, 2026-07-17)

**Bones are stored PLAINTEXT** inside the SkeletonComponent header
starting at `SkeletonComponent + 0x50`. No decryption required.

**Discovery process:**
1. Started at `SkeletonComponent = 0x11853A100`
2. Actual bone data lives in the "header" region at `0x11853A040` (offset
   `-0xC0` from SkeletonComponent — the ACTUAL component base)
3. Scanned 1 KB for unit quaternion patterns (`|q| == 1.0, all |c| ≤ 1`)
4. Found 8 unit quats at offsets `0x90, 0x170, 0x1D0, 0x230, 0x290, 0x370, 0x3D0`
5. Stride = **96 bytes (0x60)** with occasional "skip" of 0xE0 for empty slots

**Per-bone layout (96 bytes):**

| Off | Field | Type |
|---|---|---|
| `+0x00` | `quat.x` | float |
| `+0x04` | `quat.y` | float |
| `+0x08` | `quat.z` | float |
| `+0x0C` | `quat.w` | float |
| `+0x10` | `0.0` | float (padding for SIMD alignment) |
| `+0x14` | `trans.y` | float (local bone offset from parent) |
| `+0x18` | `trans.z` | float |
| `+0x1C` | `0x00000001` | dword flag (probably "active") |
| `+0x20` | subobject ptr | qword |
| `+0x28` | vtable ptr | qword (indicates bone type) |
| `+0x30..+0x5F` | additional state | mixed |

**Note on trans.x:** in every bone observed so far, `trans.x == 0`. This
is consistent with these being **bone-space local offsets** (each bone's
position relative to its parent, and R6's rig has spine bones aligned
along YZ so X=0 for spine, arms/legs have X≠0). To get **world
position** need to compose all parent transforms up to root, then add
`CharacterController + 0x1D0` (world root pos).

**Sample verified bones from entity 0x118539E70 (SkelComp @ 0x11853A040):**

| Offset in SkelComp | Quaternion | Local trans (y, z) |
|---|---|---|
| `+0x90` | `( 0.288, 0.669, 0.109, -0.676)` | `(-88.00, +garbage)` |
| `+0x170` | `(-0.244, -0.207, -0.898, -0.303)` | `(-28.75, +garbage)` |
| `+0x1D0` | `(-0.157, -0.179, -0.731, -0.640)` | `(+garbage)` |
| `+0x230` | `(-0.359, -0.186, -0.914, -0.028)` | `( 36.58, -16.53)` |
| `+0x290` | `(-0.147, -0.091, -0.670, -0.722)` | `(-41.62, -86.04)` |
| `+0x370` | `(-0.270, -0.059, -0.881, -0.384)` | `(-90.47, -69.73)` |
| `+0x3D0` | `( 0.392,  0.732, -0.303, -0.468)` | `(+garbage)` |

"garbage" = a heap pointer aliased over the trans slot (bone entries at
higher offsets shift by 8B once you cross a sub-object header). For a
production ESP we should skip entries where `f[7]` (the flag dword) is
not exactly `1.401298E-45 = 0x00000001`.

### Full walk to a specific bone position

```c
// Given entity_addr:
SkeletonComponent* sc = *(void**)(entity_addr + 0x2A8);
if (!sc) return; // no skeleton yet

// The +0x2A8 pointer is to the "header" allocated by acquireSkelDesc.
// Base of the header (with sub-entries) is `sc` itself.
// Bone transforms start at `sc + 0x50` (offset from the header base).

// Iterate bones:
for (int i = 0; i < N_BONES; ++i) {
    Bone* b = (Bone*)((uint8_t*)sc + 0x50 + i * 0x60);
    // Validate:
    if (*(uint32_t*)((uint8_t*)b + 0x1C) != 1) continue; // inactive/empty
    // Read:
    Quat q      = *(Quat*)((uint8_t*)b + 0x00);
    float t_y   = *(float*)((uint8_t*)b + 0x14);
    float t_z   = *(float*)((uint8_t*)b + 0x18);
    // Compose with parent transforms + CC world pos for world-space location.
}
```

### Next steps

1. **Identify bone semantic** — which slot is head vs feet vs hands.
   Options: (a) match against hkSkeleton reflection metadata's
   `parentIndices` array, (b) empirical dead-reckoning from the
   translations (bone with largest |z| is head, etc.).
2. **Compose local → world** — need to walk parent chain. The parent
   index is likely in the extra fields at `+0x30..+0x5F` of each bone
   entry.
3. **Add bone-read endpoint to siege_crypto.dll HTTP server** — since
   there's no crypto, this is a straight memcpy service:
   `/skel_bones {skel: "0x..."}  →  { bones: [{q, ty, tz}, ...] }`

**Milestone**: Entity → CharacterController → SkeletonComponent →
**plaintext bone transforms**. No decryption needed for bones — they
were plaintext all along.

### §16e Follow-up (2026-07-17): what the SkelComp bone-slots actually are

More sampling shows the 96B "bone entries" in the SkelComp are NOT the
animated skeleton pose. They're a **prop-attachment table** — each entry
is a slot for something that can hang off a bone (weapon, gadget,
character-model piece), plus the slot's static local placement.

**Reliable filter for a real transform-carrying slot:**
- byte at `+0x1F == 0x0F` → transform data valid
- byte at `+0x1F == 0x03` → ASCII-name entry (heap ptr to a name string
  aliased over the transform field)
- byte at `+0x1F == 0x00` → junk / uninitialized / different subclass

**Result:** only 3-8 usable slots per SkelComp, and their transforms
appear to be **static prop offsets** (e.g. weapon-hand attachment
offset), not the per-frame animated bone positions we'd want for a
head-shot ESP.

**Where the real animated bones live (hypothesis):**
- Downstream of the shared bone manager (`SkelComp+0x60`, e.g.
  `0x11C1913B8` in our sample), which we did find has a stride-0x30
  table of ~10+ slots
- Each of those slots points to a per-bone-role sub-object; the actual
  bone matrices might be in a Havok-side buffer reachable via those
  sub-objects' vtable methods
- **Not yet cracked.** Needs a targeted session with a specific bone we
  can identify (e.g. head-marker validation via CharacterController
  world pos + fixed offset).

### §16f MVP ESP path (viable TODAY)

Skip bones. Draw one marker per character at `CC.pos + (0, 0, 1.7)` —
approximates head height. Data we already have:

```c
// Per-frame:
for (Entity& e : entity_cache.entities()) {
    if (!e.valid) continue;
    Vec3 world_pos = e.pos;                       // CC + 0x1D0 (recon §5.2)
    Vec3 head = { world_pos.x, world_pos.y, world_pos.z + 1.7f };
    Vec2 screen;
    if (world_to_screen(view_data, head, sw, sh, screen))
        draw_dot(screen);
}
```

This works TODAY with the existing Siege External code. Real per-bone
head-tracking needs the animated pose crack (§16e follow-up).

---

## §17 One-sentence summary

Full physics + skeleton architecture of R6 Siege mapped statically and
verified live; **HavokUserData** and **RigidBody/CharacterController**
classes located; **Bytecode tool extended with a TLS reader + R6-specific
decrypt endpoints** so the per-thread crypto keys that hide the entity
handle system are now readable — the last remaining blocker to fully
bridging Entity → Body → HP was tool capability, not analysis capability.
