# Rainbow Six Siege — Internal Cheat Reverse Engineering Bible
## Session Date: April 27, 2026 | Game Version: Latest (April 2026 patch)

---

# 1. ARCHITECTURE OVERVIEW — How R6 Siege Works Internally

## 1.1 Engine: AnvilNext 2.0 (Ubisoft proprietary)
R6 Siege runs on Ubisoft's **AnvilNext 2.0** engine. Key characteristics:
- **Single monolithic executable** `RainbowSix.exe` (~497 MB mapped)
- **DX12 rendering** (via `d3d12.dll`), with kiero-based swap chain hooking for ImGui overlay
- **Entity-Component System**: entities are managed through a replication/serialization layer
- **Network replication**: entity state is replicated from server → client via serialization functions
- **ASLR**: module base changes every launch — all offsets are expressed as **RVA** (relative to module base)

## 1.2 Process Info (this session)
| Field | Value |
|---|---|
| Process | RainbowSix.exe (PID 16956) |
| Base Address | `0x7FF78AD60000` |
| Module Size | 497,049,600 bytes (~497 MB) |
| Architecture | x86-64 |
| Renderer | DirectX 12 |

## 1.3 How This Cheat Works (High-Level Flow)
```
1. DLL injected into RainbowSix.exe
2. DX12 Present hook installed via kiero → draws ImGui overlay
3. Entity hook installed → intercepts a function that processes every entity
4. Entity pointers cached in unordered_set (hk::entity → cached_entities)
5. Every frame, rendering loop iterates cached_entities:
   a. Filter: isA() checks entity type (rejects map objects)
   b. Filter: m_Status() checks alive/dead/team
   c. Read: m_Origin() gets world position (x, y, z)
   d. Transform: world_to_screen() projects 3D → 2D using view matrix
   e. Draw: snaplines, 2D/3D boxes via ImGui
```

---

# 2. THE TWO PILLARS: Entity System + View Translation

## 2.1 View Translation (Camera)

### What It Is
The **view_translation** object holds the camera's world position and the view-projection matrix. Without it, no world-to-screen projection is possible.

### How It's Found
The cheat uses an **AOB (Array of Bytes) pattern scan** to find a known constant data block in the `.rdata` section, then subtracts a fixed offset to reach the view_translation base address.

```
AOB Pattern: A4 70 7D BF 00 00 00 00 00 00 00 00 00 00 A0 40 ...
             (these are float constants used by the engine: -0.99, 5.0, -5.0, etc.)
AOB Hit Address:  0xA2689114
Offset from AOB:  -0x2E4
view_translation base: 0xA2688E30
```

### view_translation Object Layout
```
view_translation* this = AOB_addr - 0x2E4;
+0x000 ... internal engine data ...
+0x1D0 → Camera Position (ubiVector4: x, y, z, w) — world coordinates of the camera
+0x290 → View Matrix (4x4 float matrix) — combined view-projection matrix for W2S
```

### How the Camera Gets Updated
A data breakpoint on `+0x1D0` revealed the writer instruction:
```asm
movaps [r15+0x1D0], xmm0    ; at RVA 0x5A3BB8B
```
- `R15` = view_translation base pointer
- `xmm0` = camera position vector
- This runs every frame in the render pipeline

### View Matrix at +0x290
Contains a valid 4×4 projection matrix. Sample values:
```
m[0][0] = 0.358870  (horizontal FOV factor)
m[1][1] = 0.638213  (vertical FOV factor)
... standard perspective projection matrix ...
```
The old offset `+0x250` now contains all zeros — the struct grew by 0x40 bytes.

### World-to-Screen Math
```cpp
float w = vm[0][3]*world.x + vm[1][3]*world.y + vm[2][3]*world.z + vm[3][3];
if (w < 0.001f) return false;  // behind camera
float nx = (vm[0][0]*world.x + vm[1][0]*world.y + vm[2][0]*world.z + vm[3][0]) / w;
float ny = (vm[0][1]*world.x + vm[1][1]*world.y + vm[2][1]*world.z + vm[3][1]) / w;
screen.x = (displayWidth  * 0.5f * nx) + (displayWidth  * 0.5f);
screen.y = -(displayHeight * 0.5f * ny) + (displayHeight * 0.5f);
```

---

## 2.2 Entity System

### Three Layers of Entity Data
Through reverse engineering, we discovered entities exist at **three layers**:

```
Layer 1: Entity Manager / Replication Object
  ├── Has vtable pointer (in-module)
  ├── Contains metadata: entity IDs, status bitfields
  ├── Contains pointers to property tables
  └── Example: 0xADE36EA0

Layer 2: Entity Data Buffer (flat memory)
  ├── Allocated separately, pointed to by replication system
  ├── Contains actual gameplay data: position, health, etc.
  ├── Written by bulk memory copy (vmovdqu replication)
  └── Example: 0x3F894000

Layer 3: Entity Hook Function
  ├── A function called per-entity during processing
  ├── rcx = entity pointer (the buffer the cheat casts to scimitar::Entity*)
  ├── This is what the cheat hooks to discover entities
  └── ⚠️ CURRENTLY BROKEN — see below
```

### Entity Data Buffer Layout (Layer 2)
This is what `scimitar::Entity*` points to. Verified via data breakpoints:
```
Entity* this;
+0x00: uint32  entity_type_id (e.g., 6)  — STATIC, never read after init
+0x04: padding/unknown
+0x08: unknown (32-bit value)
+0x10 - +0x2F: unknown fields
+0x30: ubiVector4 m_Origin (x, y, z, w) — WORLD POSITION ← confirmed!
+0x40: ubiVector4 (likely velocity or rotation)
+0x50: (old position offset — NOW WRONG, was shifted -0x20)
+0x90: unknown data
+0xB0: was old status offset — NOW WRONG for this buffer type
```

**CRITICAL**: Position moved from `+0x50` → `+0x30`. The entire struct shifted.

### How Position Gets Written
```asm
vmovdqu [rcx+r8-0x20], ymm5   ; at RVA 0x1306132F
; RCX = entity data buffer base (e.g., 0x3F894000)
; R8  = 0x50
; Effective address = RCX + 0x50 - 0x20 = RCX + 0x30
; ymm5 = 32 bytes of position data (covers +0x30 to +0x4F)
```
This is a **bulk replication copy** — a generic memcpy-like function at RVA `0x1306132F` that copies network-replicated entity state into the local buffer. It's NOT an entity-specific function.

### Entity Replication Object Layout (Layer 1)
Found via R14 register in the replication copier:
```
ReplicationObject* at 0xADE36EA0:
+0x00: vtable ptr → 0x7FF79E06AD30 (RVA 0x1306AD30, in-module)
+0x08: ptr (0xAB8F5A80) — possibly entity list link
+0x10: ptr (0xADE371F0) — possibly next replication entry
+0x18: uint32 hash/ID (0xCFD80EC1)
+0x20: zeros
+0x28: small ints (0x2D=45, 0x12=18) — entity ID candidates
+0x30: ptr to property descriptor table (e.g., 0xADE37420)
+0x38: STATUS BITFIELD! → FA 00 00 C0 (byte3=0xFA means DEAD!)
+0x40: ptr to next property descriptor
+0x48: STATUS BITFIELD → 0E 00 00 C0 (byte3=0x0E, possibly alive)
+0x50: flags (00 01 01 01 07 ...)
```

The status pattern `XX 00 00 C0` with byte3 checks matches the cheat's `m_Status()` logic:
- `byte3 == 0xFA` → DEAD_1
- This is on the **replication object**, NOT the data buffer

### Entity Status Check (from cheat source)
```cpp
unsigned long long bitfield = *(unsigned long long*)(this + 0xB0);
unsigned char byte3 = (bitfield >> 24) & 0xFF;  // bits 24-31
unsigned char byte4 = (bitfield >> 32) & 0xFF;  // bits 32-39
if (byte3 == 0xFA) return DEAD_1;
if (byte4 == 0x80) return DEAD_2;
if (byte4 == 0x02) return TEAM;
if (byte4 == 0x00) return LOCAL;
return VALID;
```
The status bitfield format `XX 00 00 C0 XX 00 00 00` was found at +0x38 in the replication object.
If the cheat's Entity* once pointed to the replication object (not the data buffer), then:
- Old status at `+0xB0` needs remapping
- The data buffer and replication object may have been merged/split in the update

---

# 3. THE ENTITY HOOK PROBLEM

## What the Hook Does
```cpp
// hooks.hpp — installs a 12-byte inline hook (mov rax, addr; jmp rax)
void* entity_call = (void*)(ImageBase + ENTITY_RVA);
hook_fn(entity_call, hk::entity);

// entity_hook.cpp — the hook handler
__int64 hk::entity(__int64 rcx) {
    if (valid_pointer(rcx)) {
        cached_entities.insert((Entity*)rcx);  // cache every entity we see
    }
    return spoof_call(original_trampoline, rcx);  // call original
}
```
The hook intercepts a function that the engine calls **once per entity per frame** (or per tick). The first argument `rcx` is the entity pointer. The cheat just caches it.

## The Problem: Function at 0x4C55AA0 Gets ZERO Hits
We set an execution breakpoint on `0x7FF78F9B5AA0` (ImageBase + 0x4C55AA0) — **zero hits during active gameplay**. This function is never called.

**Possible reasons:**
1. The function was inlined by the compiler in the new build
2. The vtable call was replaced with a different mechanism
3. The entity serialization path changed entirely
4. The RVA identified via AOB was a similar but wrong function

## Next Steps to Find the Real Entity Function
1. **Approach A**: Find who reads the entity data buffer — set data breakpoint on a LIVE entity's position being READ (not written). The reader's call stack will reveal the entity iteration loop.
2. **Approach B**: Find the entity vtable at RVA `0x1306AD30` and check all its virtual function entries — one of them is the entity processing function.
3. **Approach C**: Scan for the entity list/array — find the container that holds all entity pointers, then trace what iterates it.

---

# 4. OFFSET CHANGE SUMMARY

## ✅ Confirmed & Updated
| What | File:Line | Old Value | New Value | How Confirmed |
|---|---|---|---|---|
| Entity hook RVA | hooks.hpp:64 | 0x4C55DE0 | 0x4C55AA0 | AOB scan (⚠️ but func not called!) |
| AOB → vt_base offset | scimitar.hpp:45 | -0x2A4 | -0x2E4 | R15 in data breakpoint |
| View matrix offset | scimitar.hpp:63 | 0x250 | 0x290 | Memory read (valid matrix vs zeros) |
| Camera position offset | scimitar.hpp:73 | 0x190 | 0x1D0 | Data breakpoint (movaps writer) |
| Entity position offset | scimitar.hpp:122 | 0x50 | 0x30 | Data breakpoint (vmovdqu writer) |

## ⚠️ Still Unverified / Broken
| What | File:Line | Old Value | Status |
|---|---|---|---|
| Entity hook function | hooks.hpp:64 | 0x4C55AA0 | ⚠️ NEVER CALLED — need new function |
| m_Status offset | scimitar.hpp:134 | 0xB0 | ❌ Not at +0xB0 in data buffer; found at +0x38 in replication object |
| isA offset | scimitar.hpp:162 | 0x1C | ❌ Unverified |

---

# 5. RAW EVIDENCE

## 5.1 Data Breakpoint: Camera Position Writer
```
Instruction: movaps [r15+0x1D0], xmm0
RVA: 0x5A3BB8B
Absolute: 0x7FF790D9BB8B
Registers:
  R15 = 0xA2688E30 (view_translation base)
  xmm0 = (35.79, -7.06, 32.89, 1.0) — camera world position
```

## 5.2 Data Breakpoint: Entity Position Writer
```
Instruction: vmovdqu [rcx+r8-0x20], ymm5
RVA: 0x1306132F
Absolute: 0x7FF79DDC132F
Registers:
  RCX = 0x3F894000 (entity data buffer base)
  R8  = 0x50
  R13 = 0x3F894000 (same as RCX — entity base)
  R14 = 0xADE36EA0 (replication object with vtable!)
  RDX = 0xD3BFED40 (source/stack — replicated data from network)
  R9  = 0x60 (copy size)
  RDI = 0x0E (entity index? 14)
  RSI = 0x32B91CC0 (another pointer)
  RBX = 0x7FF79FD91E48 (in-module pointer, likely function table)
```

## 5.3 Entity Data Buffer at 0x3F894000 (96 bytes)
```
+0x00: 06 00 00 00 00 00 00 00  — entity type ID = 6
+0x08: 06 00 00 00 1D 00 00 00
+0x10: 0A 00 00 00 00 00 00 00
+0x18: 00 00 00 00 00 00 00 00
+0x20: 00 00 00 00 00 00 00 00
+0x28: 00 00 00 00 00 00 00 00
+0x30: [position X] [position Y]  ← m_Origin starts here
+0x38: [position Z] [position W]
+0x40: 00 00 00 00 00 00 80 3F  — (0.0, 1.0)
+0x48: 00 00 00 00 ...
```

## 5.4 Replication Object at 0xADE36EA0 (80 bytes)
```
+0x00: 30 AD 06 9E F7 7F 00 00  — vtable: RVA 0x1306AD30
+0x08: 80 5A 8F AB 00 00 00 00  — ptr
+0x10: F0 71 E3 AD 00 00 00 00  — ptr
+0x18: C1 0E D8 CF 00 00 00 00  — hash
+0x20: 00 00 00 00 00 00 00 00  — zeros
+0x28: 2D 00 12 00 00 00 00 00  — IDs (45, 18)
+0x30: 20 74 E3 AD 00 00 00 00  — ptr to property table (DEAD entity → zeros)
+0x38: FA 00 00 C0 FA 00 00 00  — STATUS: byte3=0xFA → DEAD!
+0x40: 20 76 E3 AD 00 00 00 00  — ptr to next property
+0x48: 0E 00 00 C0 0E 00 00 00  — STATUS: byte3=0x0E → possibly alive
```

## 5.5 Loaded Modules (key ones)
| Module | Base | Notes |
|---|---|---|
| RainbowSix.exe | 0x7FF78AD60000 | Main game (497 MB) |
| d3d12.dll | 0x7FFA0A950000 | DirectX 12 |
| DINPUT8.dll | 0x7FF985610000 | Input (proxy DLL injection point) |
| defaultargs.dll | 0x7FFA069E0000 | Ubisoft config |
| steam_api64.dll | 0x7FFA126F0000 | Steam integration |
| upc_r2_loader64.dll | 0x7FFA12740000 | Ubisoft Connect |

---

# 6. CHEAT SOURCE CODE STRUCTURE

```
dx12-rainbow6-internal-main/
├── rb6/
│   ├── dllmain.cpp                    — DLL entry point
│   ├── scimitar/                      — Game engine interface ("Scimitar" = AnvilNext)
│   │   ├── scimitar.hpp               — Entity class, view_translation class, W2S
│   │   ├── engine/
│   │   │   ├── havok_math.hpp         — ubiVector4, ubiViewMatrix, ubiVector2
│   │   │   └── ida_defs.hpp           — IDA-style type definitions
│   │   └── hooks/
│   │       ├── hooks.hpp              — hook_fn(), hk::init(), inline hook installer
│   │       └── fn/
│   │           └── entity_hook.cpp    — hk::entity() — caches rcx into cached_entities
│   ├── Rainbow Six Siege/
│   │   └── fn/
│   │       └── visuals_renderables.cpp — ESP rendering: boxes, snaplines, distance
│   ├── directx/
│   │   ├── d3d12hook.cpp              — DX12 Present hook via kiero
│   │   ├── Hook/hook.cpp              — DX12 command queue hook
│   │   └── Render/Render.cpp          — ImGui rendering
│   ├── utils/
│   │   └── utils.h                    — swap_inline(), valid_pointer(), scan_pattern()
│   └── External/
│       ├── imgui/                     — ImGui library
│       └── kiero/                     — Universal graphics hook
```

### Key Classes
- **`scimitar::Entity`** — cast from rcx; has m_Origin(), m_Status(), isA()
- **`scimitar::view_translation`** — singleton; has m_ViewMatrix(), m_ViewOffset(), world_to_screen()
- **`hk::entity()`** — hook function; caches entity pointers
- **`cached_entities`** — `std::unordered_set<Entity*>` shared between hook and renderer

### Rendering Pipeline
```
DX12 Present Hook (kiero) 
  → ImGui NewFrame
  → visuals_renderables(enabled)
    → for each entity in cached_entities:
        → isA() filter (ID range check)
        → m_Status() filter (alive/dead/team)
        → m_Origin() → world position
        → world_to_screen() → screen coords
        → ImGui draw calls (lines, rects)
  → ImGui Render
```

---

# 7. MCP BRIDGE FIXES APPLIED

These fixes were made to the Cheat Engine MCP bridge (`ce_mcp_bridge.lua` + `mcp_cheatengine.py`) to prevent crashes and timeouts during reverse engineering:

| Fix | File | Details |
|---|---|---|
| `read_integer` crash | ce_mcp_bridge.lua:692 | `toHex()` on float → `tostring()` |
| Live command logging | ce_mcp_bridge.lua:5998 | `[CMD] >> method` / `[CMD] << method OK (Xs)` |
| `scan_all` crash protection | ce_mcp_bridge.lua:854 | pcall around `waitTillDone()` |
| `scan_all` missing types | ce_mcp_bridge.lua:882 | Added array/aob varType support |
| `next_scan` crash | ce_mcp_bridge.lua:982 | pcall around `foundlist.destroy()` |
| `next_scan` missing value | ce_mcp_bridge.lua:970 | Pass value for bigger/smaller scans |
| Python timeout | mcp_cheatengine.py:155 | 120s → 30s default |
| Slow commands | mcp_cheatengine.py:169 | evaluate_lua, next_scan, scan_all get 4× timeout |

---

# 8. WHAT STILL NEEDS TO BE DONE

## ⚠️ Priority 1: Find the REAL entity hook function
The function at RVA `0x4C55AA0` gets zero calls. Need to find the function the engine calls per-entity. Approaches:
1. Set read breakpoint on a **live** entity's position (find live entity first)
2. Walk the vtable at RVA `0x1306AD30` and test each function
3. Search for entity list iteration patterns

## ⚠️ Priority 2: Verify entity struct offsets
- `m_Origin`: `+0x30` (confirmed via data breakpoint, was `+0x50`)
- `m_Status`: unknown — was `+0xB0`, found at `+0x38` in replication object
- `isA`: unknown — was `+0x1C`, needs verification

## ⚠️ Priority 3: Determine if Entity* = data buffer or replication object
The cheat casts rcx directly to `scimitar::Entity*`. We need to know:
- Does the hook function receive the data buffer (0x3F894000 style) or the replication object (0xADE36EA0 style)?
- If it's the replication object, ALL offsets in scimitar::Entity need complete rework
- If it's the data buffer, only position shifted and status/isA need finding within the buffer

---

# 9. SESSION 2 BREAKTHROUGH — Entity Array & Layered Object Discovery
## (April 27, 2026 — PID 1816, Base 0x7FF72DAF0000)

## 9.1 The Entity Array — Found It!
Through pointer-tracing from a live entity data buffer (`0x410E8000`), we discovered an **entity array** at `0x1BDF96E0` with the following structure:

```
Each entity record = 0x80 bytes:
+0x00:  ptr → ENTITY REPLICATION OBJECT (e.g., 0x213E9B00)
+0x08:  ptr → property/component table (e.g., 0x231F8418)
+0x10:  uint32 = 0xFFFFFFFF (sentinel/-1)
+0x14:  zeros
+0x18-0x1F: zeros
+0x20:  ptr → self+0x50 (back-reference / second vtable area)
+0x28-0x37: zeros
+0x38:  ptr → ENTITY DATA BUFFER (e.g., 0x410E8000) ← KEY!
+0x40:  uint32 = small ID (e.g., 0x11BF4 = 73204)
+0x48-0x7F: zeros
```

Records are **contiguous** at 0x80-byte stride:
- 0x1BDF9600 → entity record (data ptr 0x410E5000)
- 0x1BDF9680 → entity record (data ptr 0x410E7000)
- 0x1BDF96E0 → entity record (data ptr 0x410E8000)
- 0x1BDF9760 → entity record (data ptr 0x410E9000)
- ...

Entity data buffers are spaced 0x1000 (4 KB) apart, suggesting page-aligned per-entity allocation.

## 9.2 Replication Object Layout (Layer 1 — REVISED)
Reading `0x213E9B00` (the entity object pointed to from array `+0x00`):
```
+0x00:  vtable ptr → 0x7FF740DDF8F0  RVA 0x132EF8F0  ← PRIMARY VTABLE
+0x08:  uint64 = 0x35773530 (type marker / class tag — same across instances!)
+0x10:  uint32 = 0x00800066 ← STATUS BITFIELD (low byte 0x66 stable, high byte changes)
+0x14:  uint32 = 0x00000100 (more flags)
+0x18:  uint32 = 0x00000001 (alive flag?)
+0x20:  ptr   → 0x3B623BC0 (component or owner)
+0x28:  zeros
+0x30:  uint32 = 0x00000400
+0x40:  ptr   → self+0x08 (self-reference)
+0x50:  vtable ptr → 0x7FF740D2D0E8  RVA 0x132E30E8  ← SECONDARY VTABLE (multi-inheritance)
+0x58:  uint64 = 1
+0x60:  ptr   → 0x3B5F37C0 (component)
+0x70:  uint32 = 0x17 / 0x15 (varies between entities — INSTANCE ID candidate!)
+0x74:  uint32 = 0x00000400
+0x78:  uint32 = 1
```

**Critical confirmation**: Two distinct entities (`0x213E9B00` and `0x213E99C0`, 0x140 bytes apart) share:
- Same primary vtable (`0x132EF8F0`)
- Same secondary vtable (`0x132E30E8`)
- Same `+0x08` type marker (`0x35773530`)
- Same low byte of status (`0x66`)
- DIFFERENT high byte of status and `+0x70` instance IDs

This is a stable **entity type signature** — same class, different instances.

## 9.3 Entity Data Buffer Layout (Layer 2 — REVISED for new build)
Buffer at `0x410E8000` (4 KB pages, page-aligned):
```
+0x00:  uint32 = 0x96 (counter / version) — varies per frame
+0x04:  uint32 = 0
+0x08:  uint32 = 0xFFFFC0 (or similar)  
+0x10:  uint32 = 0x00002002 (header flags)
+0x14-0x4F: rotation matrix / quaternion (3x4 floats with rotation values)
+0x58:  float ≈ 0.01 (timing/delta?)
+0x60:  float X  ← POSITION X ✅ CONFIRMED!
+0x64:  float Y  ← POSITION Y
+0x68:  float Z  ← POSITION Z (matches camera Z!)
+0x6C:  float W (1.0)
+0x70:  vec3 — secondary position (camera-relative? velocity?)
+0x80:  scale (5.0, 5.0)
+0x90+: more rotation/orientation data
```

**EVIDENCE**: Position read at `0x410E8060` two times during gameplay:
- Read 1: (46.87, -6.30, 32.89)
- Read 2: (26.56, -7.32, 32.89)

Z coordinate stable at **32.89** = exactly the camera Z. Entity is on the same vertical level as camera = a **player operator**.

## 9.4 The Skeleton Buffer (Layer 3 — Bones)
Earlier-discovered buffer `0x3E8A2F80` is a **bone/skeleton buffer**, NOT the entity data buffer. Each bone block is `0x80` bytes:
```
+0x00-0x2F: 3x4 rotation matrix (bone-local)
+0x30-0x3F: vec4 position (bone world position)
+0x40-0x4F: scale (1,1,1,1)
+0x50-0x5F: AABB bounds (FLT_MAX, -FLT_MAX markers)
+0x60-0x7F: parent indices, metadata
```
Total: ~76 bones (count seen at `+0x18` of the bone-buffer wrapper = 0x4C = 76).

## 9.5 The Three-Layer Architecture (CONFIRMED)
```
ENTITY ARRAY (0x1BDF96E0, stride 0x80)
    │
    ├─[+0x00]─→ REPLICATION OBJECT (0x213E9B00)
    │            ├─ vtable: RVA 0x132EF8F0  ← entity processing functions
    │            ├─ vtable: RVA 0x132E30E8  ← secondary interface
    │            ├─ status @ +0x10 (bitfield)
    │            └─ instance ID @ +0x70
    │
    ├─[+0x38]─→ ENTITY DATA BUFFER (0x410E8000, 4 KB)
    │            ├─ position @ +0x60 (x, y, z, w)
    │            ├─ rotation matrix @ +0x14
    │            └─ secondary data @ +0x70
    │
    └─ separate from bone buffer (allocated per-skinned-mesh)
                  ↓
                 SKELETON BUFFER (0x3E8A2F80)
                  └─ array of 0x80-byte bone matrices
```

## 9.6 Updated Offset Map
| Field | Layer | Offset | Confirmed By |
|---|---|---|---|
| Entity array stride | Array | 0x80 | Pattern repetition |
| Entity record → repl obj | Array | +0x00 | Pointer trace |
| Entity record → data buf | Array | +0x38 | Pointer trace |
| Entity record → entity ID | Array | +0x40 | Small int field |
| Repl obj vtable (primary) | Repl | +0x00 | RVA 0x132EF8F0 |
| Repl obj vtable (secondary) | Repl | +0x50 | RVA 0x132E30E8 |
| Repl obj status bitfield | Repl | +0x10 | Bit pattern stable |
| Repl obj instance ID | Repl | +0x70 | Varies per entity |
| Data buf position | Buf | +0x60 | Live read, Z=camera Z |
| Bone matrix stride | Bones | 0x80 | Pattern repetition |
| Bone position in matrix | Bones | +0x30 | Float pattern |

## 9.7 Path Forward
1. **Find entity array start** — scan upward from 0x1BDF9600 for the array header (count, capacity)
2. **Hook the entity processing function** — the primary vtable at `RainbowSix.exe+0x132EF8F0` likely has the per-frame entity tick function. Walk vtable[0..N], test which is called per-frame.
3. **scimitar::Entity should point to the REPLICATION OBJECT** (with vtables) — that's where status/type live. Position should be read via repl_obj's data_buf pointer.
4. **For ESP**: read position from data buffer `[entity+0x40] + 0x60`, status from repl obj `[entity+0x10]`, vtable for type from `[entity+0x00]`.

---

# 10. SESSION 3 — Entity Array & Manager Discovery (CORRECTED)

## 10.1 ⚠️ Correction: Entity Record Stride is 0x60, NOT 0x80
Earlier estimate of 0x80 was wrong by 0x20. Verified by byte-by-byte read:

```
ENTITY RECORD (0x60 bytes — 96 bytes):
+0x00: ptr → ENTITY OBJECT (e.g., 0x213E9B00)
+0x08: ptr → property/component table (e.g., 0x231F8418)
+0x10: uint32 = 0xFFFFFFFF (sentinel)
+0x14: zeros
+0x18-0x1F: zeros
+0x20: ptr → self+0x50 (back-reference)
+0x28-0x3F: zeros
+0x40: ptr → ENTITY DATA BUFFER (e.g., 0x410E8000) ← was wrongly +0x38
+0x48: uint32 = small ID (e.g., 0x15BC5)
+0x50-0x5F: zeros
```

## 10.2 The Entity Array — Confirmed 55+ Entities (this session)
At `0x1BDF96E0` (heap) we have a contiguous array of 55+ records, each 0x60 bytes:

| record # | record addr | entity ptr | data buf | idx field |
|---|---|---|---|---|
| 0 | 0x1BDF8E40 | 0x213E8CA0 | 0x410D1000 | 0 |
| 1 | 0x1BDF8EA0 | 0x213E8D40 | 0x410D2000 | 1 |
| ... | ... | ... | ... | ... |
| 23 | 0x1BDF96E0 | 0x213E9B00 | 0x410E8000 | 23 |
| ... | ... | ... | ... | ... |
| 47 | 0x1BDF9FE0 | 0x213EAA00 | 0x41105000 | 47 |

ALL share the same primary vtable `RainbowSix.exe+0x132EF8F0` (RVA `0x132EF8F0`).
Entity data buffers are 4 KB apart and page-aligned.
Index field `+0x6C` of the entity object = sequential 0,1,2,...

## 10.3 The Entity MANAGER — Found in Heap Region
At `0x3577E500` (heap) is a slot in the **entity class manager**. Each slot describes one entity instance:

```
MANAGER SLOT (~0x120 bytes):
+0x00: ptr → some array (e.g., 0x34FC2D40)
+0x10: uint32 = 0x66 (status low byte)
+0x14: uint32 = 0x84 (status high byte)
+0x1C: uint32 = entity count (e.g., 768)
+0x40: ptr → array (back-ref)
+0x48: uint32 = 0x10001 (capacity flags)
+0x50: uint32 = 0x123 (some count)
+0x58: ptr → ENTITY CLASS METADATA VTABLE (RVA 0x133D3188) ← STATIC SIGNATURE
+0x70: uint32 = 0xC0000000 (high-bit flags)
+0x80: ptr → property table
+0x88: ptr → self+0x50 (back-ref)
+0x90: ptr → ENTITY OBJECT (e.g., 0x213E9AB0)
+0xD8: ptr → ENTITY ARRAY (e.g., 0x1BDF9660 — our entity array - 0x80!)
+0xE8: 0x66 0x84 type tag again
```

**Found 410 manager slots in region `0x35770000-0x35800000`** all sharing the same metadata vtable. Each slot manages one entity instance of the class. Strides vary 0x120-0x130 bytes.

## 10.4 Entity Class Metadata Vtable (STATIC ANCHOR)
At `RainbowSix.exe+0x133D3188` is a vtable of class-specific functions:
```
RVA 0x133D3180 (vtable for class):
[0x00]: RVA ~0x215001B0  (constructor / init?)
[0x08]: RVA ~0x1197DD0   ← THE ANCHOR POINT
[0x10]: RVA ~0x5F3440
[0x18]: NULL
[0x20]: RVA ~0x1205C4F0
[0x28]: RVA ~0x11C1DA70
[0x30]: RVA ~0xD8A170
[0x38]: RVA ~0x125A110 ...
```

**This is the static anchor we can use.** Code that creates entities of this class references RVA `0x133D3188`. By scanning for `lea reg, [rip + offset_to_0x133D3188]` patterns, we can find the entity creation/iteration code.

## 10.5 Entity Object Vtable Functions (RVA 0x132EF8F0)
Eight virtual functions visible:
```
[0]:  RVA 0x1190B30  — likely destructor / OnDestroy
[1]:  RVA 0xC9D9D0   — likely OnCreate / Init
[2]:  RVA 0x11A26D0  — common per-entity call
[3]:  NULL
[4]:  RVA 0x1227840
[5]:  RVA 0x11A6A10
[6]:  RVA 0x11D4680
[7]:  NULL
[8]:  RVA 0x11A3060  ← old cheat hook target offset 8 = 0x40 — HOT?
[9]:  RVA 0x1156680
[10]: RVA 0x114D1A0
[11]: NULL
[12]: RVA 0x5AFE5A0
[13]: RVA 0xD28AC0
[14]: RVA 0x616D910
[15]: RVA 0x616D950
```

**Hook candidates**: vtable[2], [4], [5], [6] are likely per-frame functions. Setting an execution breakpoint on each and counting hits per second will identify the real hook target.

## 10.6 Confirmed Layered Object Map
```
ENTITY MANAGER REGION (heap, 0x35770000-0x35800000)
├── 410+ slots, each 0x120 bytes
└── Each slot contains:
    ├── Static metadata pointer @ +0x58 → RVA 0x133D3188
    ├── Entity object pointer @ +0x90 → 0x213EXXXX
    └── Entity array pointer @ +0xD8 → 0x1BDF9XXX

ENTITY ARRAY (heap, 0x1BDF8E40 base)
├── Records of 0x60 bytes
├── 55+ entities indexed 0..47 visible
└── Each record contains:
    ├── Entity object ptr @ +0x00
    ├── Property table ptr @ +0x08
    ├── Data buffer ptr @ +0x40
    └── Sentinel -1 @ +0x10

ENTITY OBJECT (heap, 0x213EXXXX, ~0x140 bytes)
├── Primary vtable @ +0x00 → RVA 0x132EF8F0
├── Type marker @ +0x08 = 0x35773530
├── Status bitfield @ +0x10
├── Secondary vtable @ +0x50 → RVA 0x132E30E8
└── Sequential index @ +0x6C

ENTITY DATA BUFFER (heap, 0x410EXXXX, 4 KB each, page-aligned)
└── (Layout varies — position appears at +0x60 for active entities,
    but most slots show 0,0,0 indicating dormant or differently-typed entities)
```

## 10.7 Updated Path Forward
1. **Find static pointer to entity manager**: scan for AOB pattern referencing RVA `0x133D3188` — this is the most stable anchor since it's a static metadata vtable address baked into code.
2. **Identify the hook function**: set execution breakpoints on entity vtable[2], [4], [5], [6] (RVAs `0x11A26D0`, `0x1227840`, `0x11A6A10`, `0x11D4680`) and count hits/second. The one called ~60 times/sec per entity is the per-frame tick = our hook target.
3. **Re-verify position offset across entity types**: most entities show (0,0,0) at data buffer +0x60. Either layout differs per class, or position is read from elsewhere when entity is active. Need to find a guaranteed-active entity (the local player) and inspect.
4. **For now, the cheat can use**: entity object base (`record + 0x00`) for status (`+0x10`), data buffer (`record + 0x40`) for position (`+0x60`).

## 10.8 ⭐ STATIC ANCHOR FOUND — Entity Manager Slot Constructor
**RVA `0x4CC5350`** is the unique code location that loads the entity class metadata vtable address.

The instruction:
```asm
0x7FF7327B5350: 48 8D 05 31 DE 70 0E    lea rax, [rip+0xE70DE31]    ; → 0x7FF740EC3188 (metadata vtable)
0x7FF7327B5357: 48 89 07                mov [rdi], rax              ; install vtable in slot
```

Function context (starts before 0x7FF7327B5290):
```asm
mov edx, 0x118                  ; allocation size = 280 bytes
call [rax+8]                    ; allocator returns slot ptr in rax
mov rdi, rax                    ; rdi = new manager slot
test rax, rax / je              ; null check
lock inc [...]                  ; reference count
... (zero-init slot fields) ...
lea rax, [rip+0xE70DE31]        ; ← STATIC ANCHOR (RVA 0x4CC5350)
mov [rdi], rax                  ; install metadata vtable at slot+0x00
mov rax, 0x8400000004
mov [rdi+0xE0], rax             ; install type tag (matches our 0x66 0x84 finding)
mov [rdi+0xEC], r14d            ; install count from r14d
mov qword [rdi+0xF0], 1
mov [rdi+0xF8], 0xC0
mov rcx, rdi                    ; arg1 = slot
mov rdx, [rsp+0x60]
mov r8d, 0x10008                ; arg3 = capacity flags (matches +0x48 in slot!)
xor r9d, r9d
call 0x7FF72ED1FC00             ; allocates the entity array within the slot
```

**Confirms**: manager slot is **0x118 bytes** (we estimated 0x120 — close enough). Strides 0x120/0x130 in the heap region are with alignment.

### How To Use This Anchor (For Cheat)
```cpp
// 1. Scan for the unique 7-byte LEA pattern at runtime:
//    "48 8D 05 ?? ?? ?? ??" within executable section
//    Verify each match: target = (lea_addr + 7) + sign_extend(disp32)
//    The unique match is the constructor at RVA 0x4CC5350
auto constructor_rva = scan_unique_lea_to(0x133D3188);  // -> 0x4CC5350

// 2. From the constructor, find callers (functions that instantiate entity manager slots)
//    Each caller is a class registrar — the master registrar references the global manager.

// 3. OR just hook this constructor: every entity-manager-slot allocation passes through here.
//    rdi (after rax->rdi mov) = new slot. Capture rdi and you have a pointer to every
//    entity instance ever created.
```

## 10.9 Confirmed Static RVAs (for cheat update)
| Asset | RVA | Description |
|---|---|---|
| Entity object vtable | `0x132EF8F0` | All entities of this class share |
| Entity object secondary vtable | `0x132E30E8` | Multi-inheritance interface |
| Entity class metadata vtable | `0x133D3180` | Class factory/metadata |
| Entity manager slot constructor | `0x4CC5350` | **STATIC ANCHOR** for finding manager |
| View translation AOB target offset | `-0x2E4` | From AOB hit |
| View matrix offset | `+0x290` | From view_translation base |
| Camera position offset | `+0x1D0` | From view_translation base |
| Entity record stride | `0x60` | In entity array |
| Entity record → data buf offset | `+0x40` | Within record |
| Entity record → object offset | `+0x00` | Within record |
| Entity record → property offset | `+0x08` | Within record |

## 10.10 Recommended Cheat Architecture (clean rewrite)
Instead of hooking a function (which broke after the update), the cheat should:
1. **Find manager via AOB**: scan for the unique LEA pattern targeting RVA `0x133D3188`
2. **Hook the constructor at RVA `0x4CC5350`**: capture every slot pointer (rdi) into `cached_slots`
3. **Per-frame**: iterate `cached_slots`, read entity object via `slot+0x90`, read array via `slot+0xD8+0x80` (the actual array start)
4. **Per-entity**: read position from `data_buf+0x60`, status from `obj+0x10`, type from vtable check at `obj+0x00`

This is **far more stable** than the old approach because:
- The constructor is naturally called for each entity manager slot
- The slot structure is well-defined (0x118 bytes, fixed offsets)
- The static metadata vtable is a permanent anchor

---

# 11. SUMMARY OF SESSION 3 FINDINGS

✅ **Entity record stride corrected**: 0x60 bytes (not 0x80)
✅ **Entity data buffer pointer is at +0x40** (not +0x38)
✅ **55+ entities found** in array at `0x1BDF8E40` (heap, ASLR-randomized)
✅ **410 entity instances of one class** found in manager region `0x35770000`+
✅ **Entity manager slot layout** mapped (0x118 bytes, key offsets +0x58, +0x90, +0xD8)
✅ **Static anchor RVA `0x4CC5350`** — unique LEA instruction loading metadata vtable
✅ **Entity object vtable functions cataloged** (16 entries at RVA 0x132EF8F0)
✅ **MCP bridge stability fixes applied** (removed timeout threads, added pcall safety)

⏳ **Still TBD**: which vtable function is the per-frame entity tick (hook target)
⏳ **Still TBD**: position offset for non-active/dormant entities (most show 0,0,0)
⏳ **Still TBD**: complete master game manager (the parent of all entity classes)

---

# 12. SESSION 4 — LOCAL PLAYER ANCHORED + POSITION CORRECTED

## 12.1 ⭐ Local Player Found
By scanning all entities for positions matching the live camera, we identified the **local player entity**:

```
Camera: (42.00, -5.56, 32.89)
LOCAL PLAYER:
  entity_record  = 0x1BDF91A0 (heap, ASLR)
  entity_object  = 0x213E9240 (heap)
  data_buffer    = 0x410DA000 (heap)
  position       = (41.85, -4.50, 32.89)  ← Z exactly matches camera!
  status         = 0x00800066
  entity_id      = 9 (at object+0x68)
```

The 0x800066 status pattern is consistent across all live entities. Only 3 entities had valid world coordinates — the local player and 2 entities at (-40.71, -28.11, -20.71) which are likely paired body+weapon meshes for a single remote operator OR dummy spawn points.

## 12.2 ⚠️ POSITION OFFSET CORRECTED: +0x50, not +0x60
Earlier we noted position at `data_buf + 0x60`. **THAT WAS WRONG**. The correct offset is:
```
data_buf + 0x50: float X
data_buf + 0x54: float Y
data_buf + 0x58: float Z
data_buf + 0x5C: float W (1.0)
```

Verified by direct read on local player buffer 0x410DA000:
- `+0x50` = (41.85, -4.50, 32.89) ← matches camera ✓
- `+0x60` = (-0.99, -0.11, -0.02) ← rotation/normal vector

## 12.3 The Property Table Holds D3D12 Resources
The property table at `entity_object + 0x90` (e.g., 0x231F82C8 for local player) contains 30+ entries each 0x18 bytes. All point to objects in **D3D12Core.dll** — these are GPU resources (descriptor heaps, buffers, textures), NOT gameplay components.

```
Property table entry (0x18 bytes):
+0x00: uint32 (zeros usually)
+0x04: uint32 (0x84 type tag)
+0x08: uint32 flags (0x100, 0x300, 0x400 etc — sub-type)
+0x0C: uint32 (0xAC3 type id - constant)
+0x10: ptr → D3D12 object (vt = D3D12Core.dll+0x24F3A0 or similar)
```

This means the array we found is the **renderable mesh array**, not gameplay entity array. For ESP this is fine (positions work). For HP/team/weapon, a different anchor is needed.

## 12.4 Cheat Usage Reality Check
Inspection of cheat source confirms the cheat **does NOT actually display health**:
- `Render::DrawPlayerTags(Health, MaxHealth, ...)` is defined in `Render.cpp` but **never called** anywhere in the codebase
- Visuals_renderables.cpp only does position/distance ESP
- So the renderable mesh array is sufficient for the cheat's actual feature set

## 12.5 Final Confirmed Offsets for Cheat Update
```cpp
// Entity record stride
constexpr size_t ENTITY_RECORD_STRIDE = 0x60;

// Within entity record (e.g., at 0x1BDF91A0):
constexpr size_t REC_TO_ENTITY_OBJ  = 0x00;  // ptr to entity object
constexpr size_t REC_TO_PROP_TABLE  = 0x08;  // ptr to D3D12 property table
constexpr size_t REC_SENTINEL       = 0x10;  // 0xFFFFFFFF
constexpr size_t REC_TO_DATA_BUF    = 0x40;  // ptr to data buffer (was wrongly +0x38)

// Within entity object (e.g., at 0x213E9240, size 0xA0):
constexpr size_t OBJ_VTABLE         = 0x00;  // = RBSIX+0x132EF8F0
constexpr size_t OBJ_TYPE_MARKER    = 0x08;  // = 0x35773530 (constant)
constexpr size_t OBJ_STATUS         = 0x10;  // bitfield (0x00800066 = active rendered)
constexpr size_t OBJ_VTABLE2        = 0x50;  // = RBSIX+0x132E30E8
constexpr size_t OBJ_ENTITY_ID      = 0x68;  // unique ID (e.g., 9 = local player)
constexpr size_t OBJ_PROP_TABLE     = 0x90;  // D3D12 property table

// Within data buffer (e.g., at 0x410DA000, 4KB page):
constexpr size_t BUF_POSITION       = 0x50;  // float X,Y,Z (was wrongly +0x60)
constexpr size_t BUF_ROT_QUAT       = 0x60;  // rotation/normal vector
```

## 12.6 Identifying Local Player Programmatically
The cheat can identify which entity is the local player by:
1. Read camera position from `view_translation + 0x1D0`
2. For each entity: read position from `data_buf + 0x50`
3. The one with `distance < 1.5m` from camera is the local player
4. All others are remote players / NPCs / props

Filter for `status == 0x00800066` to skip dormant/destroyed entities.

---

# 13. R6 VERIFIER — External validation tool

A standalone Win32 console exe that reads RainbowSix.exe via `ReadProcessMemory` and walks every documented structure was added under `r6_verifier/`.

## 13.1 Layout

```
r6_verifier/
├── r6_verifier.sln              VS 2022 / 2026 solution
├── README.md
└── r6_verifier/
    ├── r6_verifier.vcxproj
    ├── r6_verifier.vcxproj.filters
    ├── main.cpp                 6-stage verifier driver
    ├── logger.hpp               ANSI-coloured `[ OK ] / [WARN] / [FAIL]` printing
    ├── process.hpp              Process attach + RPM helpers
    ├── scanner.hpp              AOB scanner + LEA-target finder
    └── structures.hpp           Every offset / RVA mirrored from this notes file
```

Built artefact: `r6_verifier/x64/Release/r6_verifier.exe` (53 KB, no external deps).

## 13.2 Stages performed by `r6_verifier.exe`

| # | Stage                          | Verifies                                                                |
|---|--------------------------------|-------------------------------------------------------------------------|
| 1 | Process & module attach        | base + size, readable                                                    |
| 2 | Static vtables                 | RVA `0x132EF8F0`, `0x132E30E8`, `0x133D3180` — function pointers in module |
| 3 | AOB anchor                     | unique `lea` to metadata vtable resolves to RVA `0x4CC5350`              |
| 4 | Entity array walk              | record stride 0x60, sentinel 0xFFFFFFFF, vtables match, positions/dirs   |
| 5 | View translation / camera      | resolves view struct, prints camera vec3                                 |
| 6 | Manager-slot class diversity   | sweeps 0x30000000–0x40000000, ranks distinct classes by instance count   |

## 13.3 Mapping notes -> code constants (kept in sync)

`r6_verifier/r6_verifier/structures.hpp` is the single source of truth that
mirrors every constant in this notes file.  When the notes change, update
`structures.hpp` and rebuild — the verifier will then re-confirm or invalidate
the new offsets.

## 13.4 Build & run

```
# from a Developer Command Prompt for VS 2022/2026:
msbuild r6_verifier\r6_verifier.sln /p:Configuration=Release /p:Platform=x64

# run as Administrator (game process needs PROCESS_VM_READ):
r6_verifier\x64\Release\r6_verifier.exe
```

Build was performed successfully on this machine with **MSBuild 18.5.4** (VS 2026 Community v143 toolset, C++20). The vcpkg system-wide post-build script emits a few benign warnings that can be ignored — the actual binary is produced regardless.

---

# 14. SESSION 5 — Verifier-driven discoveries

Running `r6_verifier.exe` (v1.1) while the game was sitting at the **main menu** (not in a match) produced findings that change our understanding of the entity ecosystem.

## 14.1 Module + static structures CONFIRMED stable

| Stage | Result   | Note                                                       |
|------:|----------|------------------------------------------------------------|
| 1     | OK       | RainbowSix.exe base+size match, 474 MB                     |
| 2     | OK       | All 3 documented vtables intact, fn ptrs in module         |
| 3     | OK       | Unique LEA at RVA `0x4CC5350` resolves to metadata vtable  |

So everything STATIC in the binary is right.  Anything documented that lives in heap memory may or may not be present depending on whether the game is in-menu vs in-match.

## 14.2 The entity ecosystem is FAR larger than the renderable mesh class

Stage 6 of the verifier sweeps committed private heap regions for any qword
at `slot+0x58` that points into the documented metadata-vtable RVA range.
Even **at the menu**, we observed:

| Metric                              | Value     |
|-------------------------------------|----------:|
| committed private regions scanned   | 513       |
| bytes scanned                       | 780.8 MB  |
| total slot candidates               | 124,825   |
| **distinct entity classes**         | **3,954** |

Top 20 menu-time entity classes by instance count:

| #  | metadata RVA   | instances |
|----|----------------|----------:|
| 1  | `0x134B7370`   | 40,957    |
| 2  | `0x133BC8B8`   | 10,000    |
| 3  | `0x1309A898`   |  9,163    |
| 4  | `0x134990F0`   |  7,500    |
| 5  | `0x132519F0`   |  4,999    |
| 6  | `0x13322498`   |  4,999    |
| 7  | `0x13251690`   |  4,999    |
| 8  | `0x133224D8`   |  4,999    |
| 9  | `0x134A66A0`   |  4,302    |
| 10 | `0x133CC040`   |  4,098    |
| 11 | `0x132C3830`   |  3,663    |
| 12 | `0x130CDD60`   |  3,453    |
| 13 | `0x13360640`   |  3,166    |
| 14 | `0x134A0A80`   |  1,280    |
| 15 | `0x13450540`   |  1,033    |
| 16 | `0x13308BB0`   |  1,024    |
| 17 | `0x13308C30`   |  1,024    |
| 18 | `0x1331A780`   |    848    |
| 19 | `0x135A5380`   |    741    |
| 20 | `0x136A5AD0`   |    622    |

Notable: our previously-documented class metadata at RVA `0x133D3180` was
**NOT** in the menu-time top list — it appears to be an in-match-only class
(probably "scimitar::Renderable" or similar).  The 4 999-instance classes
look like fixed-capacity object pools (asset references, pooled handles).

## 14.3 View translation AOB still hits 448 places

The pattern `48 8D 15 ?? ?? ?? ?? 48 8B CE E8` is wildly non-unique:
448 raw hits, of which **209** resolve into the documented `.data` RVA range.

The verifier now ranks candidates by ref-count.  Top candidate while in menu
was `RainbowSix.exe+0x13CF52FC` with **157 LEAs pointing to it** — but the
qword stored there is uninitialised (0x200007FF6 garbage), confirming the
view subsystem isn't allocated in the menu.

Future work: tighten the AOB.  The original pattern is too short.  Try
extending it with more context bytes after the `E8` call (which itself
should have a unique displacement).  We can also rule-out candidates by
demanding the target be aligned to 16 and contain a vtable-shaped pointer
when allocated.

## 14.4 Key fixes already in `r6_verifier`

The first verifier run produced false-positive entity records (`entity_obj
= 0xFFFFFFFF`) because the candidate gate only checked the sentinel and a
loose pointer range.  v1.1 of the verifier now requires:

1. `entity_obj` must be in the heap window `[0x10000000, 0x80000000)`
2. `entity_obj` must pass `VirtualQueryEx -> MEM_COMMIT`
3. The qword at `entity_obj + 0x00` (vtable) must point into RainbowSix.exe
4. The first vfn pointer must also point into RainbowSix.exe

This eliminates the false positives.

Spam on stage 5 (one debug line per candidate * 209 candidates) was capped to
the top-10 by ref count.

## 14.5 Updated TODO

- [ ] Re-run the verifier in a **live match** to see all stages green and
      validate the entity-record positions and per-class counts.
- [ ] Investigate the top-1 menu-time class at RVA `0x134B7370` (40 957
      instances) — likely a UI element pool or asset-handle pool.
- [ ] Tighten `AOB_VIEW_TRANSLATION` so the chosen struct is unique even at
      menu.
- [ ] Cross-reference the in-match dominant class RVA against the menu top-20
      list to determine which classes are gameplay-only.
