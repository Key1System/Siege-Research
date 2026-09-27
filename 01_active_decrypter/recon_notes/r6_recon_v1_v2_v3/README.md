# R6 Siege — Reverse Engineering Findings

Ethical, static-first reverse engineering of `RainbowSix.exe` (Anvil engine,
VMProtect-packed, Havok 2024.2.0 physics). No cheat development, no
modification — observational analysis only.

## Files in this folder

| File | What's in it | Read order |
|---|---|---|
| `SIEGE_RECON.md` | **v1 report (§0–§19)** — binary fingerprint, VMProtect topology, MBA obfuscation, Anvil class registry, initial entity layout | 1st |
| `siegerecon2.md` | **v2 continuation (§20–§60)** — fully detailed, includes live verification, complete Havok inventory, per-frame physics tick, Siege class taxonomy | 2nd (main report) |
| `output.md` | Earlier scratch with binary fingerprint | reference |
| `live_session_log.json` | Bytecode tool's request log from live verification | reference |
| `junk_scan.json` / `ubx_sweep.json` | Resumable script state | tooling |

## Where to start

**TL;DR of everything verified:** open `siegerecon2.md` and read:
- **QUICK INDEX** at the top (one-screen handoff for cold pickup)
- **§38** for live-memory verification methodology
- **§43, §45, §46** for Havok physics deep-dive
- **§58** for the per-frame physics tick (the big find)
- **§60** for the session summary + open questions

## Headline findings

### Binary & obfuscation
* `RainbowSix.exe` — packed with VMProtect (`.UBX0` 3 MB + `.UBX1` 129 MB)
* **MBA wrappers everywhere**: ~5,000-15,000 distinct wrappers across `.text`,
  each loading 3-4 packed globals and decoding through ~200 instructions of
  obfuscated arithmetic
* Top 1% of MBA globals account for **77.4%** of all loads (power law)
* Packed globals **rotate at runtime** (VMP key cycling)
* Ubisoft strips MSVC RTTI from R6* classes; Havok hknp* / hkReflect classes
  preserve full RTTI in `.data`

### Anvil engine (Ubisoft Montreal)
* **Class registry** at `off_7FF6D91D3E80` — slot-table with 7-bit class ID
  (max 127 classes)
* **Handle layout** `{generation:32, flags:2, slot:30}` — top 2 bits of slot
  field are preserved-across-refresh flags (likely strong-ref + something)
* **TLS-keyed in-match gate**: `TLS[+0xCCC] == 2` (= 3276 dec) — 5-way verified
* **Per-frame WORLD UPDATE STAGES** at `sub_7FF6C5F1B900`:
  0 = PrePhysics, 1 = Physics, 2 = PostPhysics, 3 = between-frames
* **Lazy RTTI registration** — each class has a helper that atomically
  publishes `{hash, name_ptr}` to a global slot

### Entity / Component system
* `BaseEntity[+0xD0]` = ComponentList ptr — **QUADRUPLE-VERIFIED**
* `BaseEntity[+0x50]` = position vec4 (xyz + W=1.0)
* `BaseEntity[+0xF8]` = Anvil handle (32:gen, 2:flags, 30:slot)
* `BaseEntity[+0x1E0..+0x22D]` = component-type-to-slot-index table
  (~78 bytes, each byte is a slot id or 0xFF = none)
* ComponentList = flat array of qword ptrs, 0xFFFFFFFF sentinel, capacity int
* Entity pool stride **0x600** in shared pools; player/special entities get
  separately-allocated heap blocks (e.g., 1.36 MB)
* Pattern: `entity[+0xD0][entity[+slot_byte] * 8]` → component ptr

### Havok 2024 physics (the goldmine)
* **133 hknp* classes + 27 hk* core classes** found via tagger inventory
* `hknpWorld` = 4432 bytes, multi-inherit (3 vtables)
* Siege overrides primary vtable (~30 vfuncs) + vtbl3 (23 vfuncs);
  vtbl2 is passthrough
* `hknpWorld[+0xB78]` = simulation engine (ST or MT)
* `hknpWorld[+0x10B0]` = character proxy manager (lazy)
* `hknpWorld[+0xE18]` = per-frame callback list
* `hknpCharacterRigidBody` = 160 bytes — character physics body
* `hknpCharacterProxyManager` = 40 bytes — character movement coordinator
* `hknpMultithreadedSimulation` = 1776 bytes
* **Two hknpEventDispatcher per world** (immediate + queued)
* Construction: `sub_7FF6CB16C4E0` (5.9 KB factory) — gated by TLS[+0xCCC]==2

### Siege-specific (R6*) classes
* 54 R6* classes catalogued
* Physics-relevant: `R6CharacterContactFilter`, `R6DefuserMassModifier`,
  `R6DestructionManagerTerminalHandler`, `R6Facility`
* Gameplay framework: `R6GameFlow`, `R6MatchmakingManager`,
  `R6SessionService`, `R6sPenaltiesService`
* Sound integration: `RollingSlidingSoundModifier`
* Destruction: triple-tier `hknpBreakable* + R6Destruction*` with material
  range check
* Camera system: 17 classes including `CameraType_Fullframe` and
  `CameraType_MicroFourThird` (real sensor format constants)

### Live memory verification
* Bytecode HTTP RPM tool (127.0.0.1:9999) — read-only RPM, no driver
* In-match: 5000+ entity instances; out-of-match: ~10
* User's entity `0x13B6324E0` walked end-to-end (vtable, ComponentList,
  DamageComponent, position vec4)
* Entity pool regions span 12+ heap arenas
* Holders for an entity: broadphase entries (with world pos + back-ref)
  + scene-graph linked list nodes (stride 0x40, entity at +0x18)

## Methodology (still applies)

1. **NEVER finalize an assumption** — verify byte patterns, decompile,
   cross-reference before claiming.
2. **Call BS on your own past claims** — every section has an
   "Anti-hallucination ledger" with retractions.
3. **Dead strings ≠ dead concepts** — `currentHealth`/`CharHealth` are
   0-xref tooling metadata; real HP comes from `HEALTH:%.2f` log output.
4. **Static + live cross-check** — both signals required for high confidence.

## Open questions for next session

* Find the actual main game loop calling the WorldUpdate stages
* Identify cheat-hook `rcx` semantics at RVA `0x4992290`
  (needs `sub_7FF6C9C35580` analysis)
* Decompile 13 KB ragdoll constructor `sub_7FF6CB0DF9B0` fully
* Walk hknpWorld vtbl3's 23 Siege overrides (physics event observers)
* Map the full Anvil class registry header layout
* Live in-match capture of an hknpWorld instance + walk members
* Bullet trace path through Havok RayCast classes

## Tools used

| Tool | Where | Notes |
|---|---|---|
| IDA Pro 9 with MCP plugin | static analysis | function discovery, decompile, byte search, type inference, py_eval scripting |
| Bytecode (HTTP-driven memory tool) | live verification | `127.0.0.1:9999`, RPM-only, no driver — read-only methodology only |

## Doc structure (siegerecon2.md sections)

* QUICK INDEX (top) — one-screen handoff
* §20 — pickup point from SIEGE_RECON.md
* §21 — DamageComponent verification
* §22-§24 — Encryption / junk cleanup
* §25-§34 — Physics / Theater / Actor systems
* §35-§37 — Player HP find via log strings
* §38 — Live memory verification (Bytecode)
* §39-§42 — Entity layout + MBA wrapper deep-dive
* §43-§47 — Havok world + character/destruction allocators
* §48 — MBA encryption layer statistics
* §49-§51 — Character proxy + dispatch table analysis
* §52-§54 — Siege class taxonomies (R6*, Gadget*, Camera*, Loadout*, etc.)
* §55-§57 — Event system + architecture summary
* §58 — Per-frame physics tick mechanism (key find)
* §59 — Siege gameplay vocabulary (DBNO, weapon names, etc.)
* §60 — Session summary + open threads
