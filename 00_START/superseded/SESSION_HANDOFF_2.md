> **SUPERSEDED 2026-09-18 — see `00_START/README.md`.**
> Kept for its detail and history. Where it disagrees with that file,
> that file is correct.

# SESSION HANDOFF 2 — read this first

**Date:** 2026-09-16
**Supersedes parts of** `SESSION_HANDOFF.md` (2026-09-15). Where they
disagree, this file is newer.

---

## 0. THE 60-SECOND VERSION

- **Bone data is fully decrypted** and streams at ~365 reads/sec.
- **Skeleton topology is SOLVED** — 20/20 biped bones with full parent
  chains, from the game's own SkeletonDescriptor. No pose variation, no
  statistics.
- **World placement is NOT solved.** Skeletons animate correctly but do
  not follow the character. This is the one thing left.
- A working reference implementation exists at
  `C:\Users\hhhuh\Downloads\vam` — it shows exactly how to finish it.

---

## 1. WHAT TO READ, IN ORDER

| # | file | why |
|---|---|---|
| 1 | this file | current state + what to do next |
| 2 | `01_active_decrypter\recon_notes\SIEGE_RECON_V5.md` **§40-§42** | the `vam` architecture, the rebuilt resolver, the entity link |
| 3 | `C:\Users\hhhuh\Downloads\vam\pose_worker.cpp` | `resolve_entity_matrix()` — the answer to the open problem |
| 4 | `C:\Users\hhhuh\Downloads\vam\skeleton_component_resolver.hpp` | content-validation method |
| 5 | `SIEGE_RECON_V5.md` §20-§39 | how the decryption was derived |

`SESSION_HANDOFF.md` (v1) is still correct for the crypto templates and
the crash rules. Its §31d/§32/§33 remap hunt is **superseded** — see §4
below.

---

## 2. TOOLING

| thing | where | note |
|---|---|---|
| internal tool | `Bytecode-Internal`, HTTP **:9998** | injected into the game |
| external tool | `Bytecode`, HTTP :9999 | `/eval` = exact 64-bit math |
| IDA MCP | **`http://127.0.0.1:13338/mcp`** | streamable HTTP, `type: "http"` |
| overlay | `SiegeSkel\SiegeSkelESP.exe` | read-only, D3D11 + ImGui |

**Rebuild + reinject loop** (no game restart needed):
```
POST /unload  ->  cmake --build build --config Release  ->  Inject.exe
```

⚠️ **PowerShell mangles unsigned 64-bit math and hex literals.** Use the
external tool's `/eval` (JavaScript BigInt) for anything arithmetic. This
cost real time more than once.

⚠️ **Never call `auto_wait()` over the IDA MCP connection** — it blocks
the transport until global analysis settles and the call times out.

---

## 3. WHAT IS SOLVED

### 3a. Decryption — all verified live

| layer | formula | evidence |
|---|---|---|
| bone buffer ptr | `ROL64(enc,4) − TLS[0x9800]` | bit-exact |
| `r15` source array | `([r10] + 0x78731A5E605CAA6) ^ rdx` | reproduced |
| prologue records | byte-wise XOR vs `[skel+0xD0]` | → valid vtable |
| MBA globals | `mask + index` | 4/4 sites |
| entity chain | `ROL64((f + K1) ^ K2, 45)` | IDA + hand |
| `m_BoneIDMap` | `{u32 hash, u16 idx}` stride 8 | 20/20 IDs |

### 3b. TLS map

```
10,673 slots · 279,848 sites · 288 MB · ~56 s
UNKNOWN 1,711 -> 955   key slots 8,162 -> 9,158   ground truth 9/9
```

The classifier had been **64-bit-register-only**. Adding 8-bit forms,
memory operands and immediates found ~900 more keys (§39).

### 3c. ⭐ Skeleton topology — SOLVED

```
1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7 -> 8 -> 9      spine / neck / head
               5 -> 31 -> 32                   arm A
               5 -> 33 -> 34 -> 35 -> 36       arm B
          2 -> 76 -> 77 -> 78                  leg A
          2 -> 80 -> 81 -> 82                  leg B
```

All 20 `kBipedBoneIds` resolved with parent + pose index. Both arms branch
from the chest, both legs from the pelvis.

**The chain:**
```
/stream                  -> bone positions, keyed by SKELETON
/entities                -> skeleton -> ENTITY          (new route)
  entity +0xD8           -> components[]                (29-bit count!)
  component +0..0x480    -> pose-pool PAIR
      shared vtable AND [pool+0x10] == entity
  [pool+0x08]            -> SkeletonDescriptor
  [desc+0x70]            -> bone hierarchy, stride 0x1C
```

Hierarchy record:
```
+0x00 u16 parent   (0xFFFF = root)
+0x04 u16 skel     <- index into the POSE buffer
+0x14 u32 id       <- bone name hash
```

---

## 4. ⚠️ CORRECTIONS TO THE OLD NOTES

| old claim | truth |
|---|---|
| count mask `& 0x3FFFFFFF` (30-bit) | **`& 0x1FFFFFFF` (29-bit)** |
| bone stride `0x40` | pose stride **`0x20`** (pos+w, then quaternion at +0x10). `0x40` is a *derived* matrix buffer |
| `[desc+0x70]` field3 = "a second index" | it is `skel`, the pose-buffer index |
| "41 bone writers" | **5** sites, 1 executing (the pattern matched `mov [rsp+0x3C],1.0f` prologues) |
| `TLS[0x18]` = bone count | it is not |
| `TLS[0x98C8]` "NOT a key" | it **is** an add-key, load-bearing |
| "~600 T2 sites", "key table at `0x7FF7A6C68440`" | both from a broken detector; that address is an MBA **mask** global |
| 99-bone vs 32-bone rigs need a remap | they are **different bone sets**; no remap exists — stop looking |

---

## 5. ❌ THE ONE OPEN PROBLEM

**Skeletons animate but do not follow the character.** Legs move, body
stays pinned, jumps only on respawn.

That symptom is diagnostic: **live local bones + stale/incorrect world
transform.** Bones are local/model space — every rig is a 1.6 m human at
the origin:

```
X -0.342..0.298   Y -0.407..0.483   Z 0.028..1.625
```

### What was tried and FAILED

Memory-proximity pairing: scan near the skeleton for a rigid 4x4 on the
floor plane. It finds real-looking matrices —

```
row0 (0,-1,0) row1 (1,0,0) row2 (0,0,1)
row3 (50.4, 5.0, 31.4, 1.0)
```

— but the **wrong** ones (spawn/reference transforms). Symptoms: prone
when standing, pinned, respawn-only jumps. **Now disabled** in the overlay
rather than left drawing nonsense.

Ruled out by probing: `skeleton+0x00..0x200`, `entity+0x00..0x400` (one
changing float at `+0x10C`, a timer), all 18 entity heap pointers, and the
registers at the bone decrypt site.

### The answer — `vam\pose_worker.cpp::resolve_entity_matrix()`

```cpp
const auto reference = read(entity + entity_transform_member_offset);
Emulator resolver(process_);
resolver.reg(UC_X86_REG_RCX, reference);
resolver.reg(UC_X86_REG_GS_BASE, process_.teb());
resolver.run(entity_transform_object_resolver, ..._return, 20000);
const auto object = resolver.reg<uint64_t>(UC_X86_REG_RAX);
read_bytes(object, matrix.data(), sizeof(matrix));
if (rigid(matrix)) ...
```

It **emulates the game's own transform resolver** (Unicorn) and reads the
matrix from the returned pointer. Same principle that worked everywhere
else: do not reimplement or guess — let the game compute it.

**Three things needed:**
1. `entity_transform_member_offset` — which entity field holds the reference
2. `entity_transform_object_resolver` — the function address (+ its return address)
3. Unicorn in the toolchain

`vam` also emulates `Reflex::GetTransforms` for live poses:
```
find struct where [+0x20] == known SkeletonComponent
  [+0x00] character_vtable   (in-module)
  [+0x30] library_character
    [library_character] -> internal
    [internal + 8]      -> abstraction
    [abstraction]       -> abstraction_vtable
    [abstraction_vtable + 0x30] -> GetTransforms     <- vtable slot 6
call with RCX=abstraction, RDX=aux_out, R8=pose_out, GS_BASE=target TEB
```

---

## 6. THE METHOD THAT WORKS

`vam`'s discipline, and the reason it succeeds where scanning did not:

**Find candidates cheaply, then ACCEPT ONLY IF CONTENT SATISFIES
INVARIANTS.**

Each SkeletonDescriptor holds **seven** arrays of identical length. The
invariant test (`parent == 0xFFFF || parent < count`, `skel < count`,
`id != 0`, ≥1 root) separates them cleanly:

```
0x28F5494F320  sane 100%  roots 1   <- the bone array
others         sane 0-19%
```

Candidates found by proximity scored 4-45% and were correctly rejected.

> **Proximity in memory is not evidence. Content is.**

---

## 7. CRASH RULES (all learned the hard way)

1. Never return `CONTINUE_SEARCH` from the VEH for a trap your own debug
   registers caused.
2. Never suspend game threads to install debug registers.
3. Never execute a copied snippet that dereferences memory unless every
   pointer operand is verified readable — **SEH will not save you**, it
   already failed to once.
4. **Validate before dereferencing inside a VEH.** A fault there kills the
   process with *no event-log record at all*. Two crashes had exactly that
   signature. `bone_range_ok()` now guards all four handler dereferences.
5. The HTTP server must handle each client on its own thread. It was
   serial, so a slow `/scan_aob` wedged it so badly the DLL could neither
   serve `/unload` nor be re-injected — the game had to be restarted.

---

## 8. PERFORMANCE NOTES

- `/bones` per frame = **2 fps** (each call arms a hardware breakpoint and
  waits out its timeout). `/stream` = **158 fps**. Always use `/stream`.
- `ReadProcessMemory` is the frame budget, not rendering. One syscall per
  actor per frame is a process switch each; throttle to ~250 Hz.
- The placement scan read **8 MB per rig per second**. That alone stalled
  the render loop.

---

## 9. NEXT STEP

1. Wire `/entities` into `esp_main.cpp` (it fetches `/stream` but not
   `/entities`, so `DescTopology` has no entity to resolve from). This
   makes descriptor edges replace the rigid-distance ones — **small, and
   the topology work is already done**.
2. Then the real task: find `entity_transform_member_offset` and the
   resolver function, add Unicorn, and emulate it.

Everything else is finished.
