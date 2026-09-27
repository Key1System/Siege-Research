# Siege Research — START HERE

**Updated 2026-09-18.** This file is the single entry point. The three
older index docs (`INVENTORY.md`, `SESSION_HANDOFF.md`,
`SESSION_HANDOFF_2.md`) are in `superseded/` — they stacked corrections on
top of each other and disagreed. Where this file and any of them differ,
**this file wins**.

Everything lives under `C:\Users\hhhuh\Downloads\Siege-Research\`.

---

## 0. The 60-second version

Target: **Rainbow Six Siege**, `RainbowSix.exe`, BattlEye not running.
All work is **read-only** and **hook-free** — see §6, those are hard rules.

Solved and verified live:

- Bone/pose decryption, streaming at ~365 reads/sec
- Skeleton topology — 20/20 biped bones with parent chains, from the
  game's own SkeletonDescriptor
- TLS block mapped — 10,673 slots, 9,158 key slots, 9/9 ground truth
- Entity enumeration without breakpoints — 4,096 entities in ~9 s
- Rig -> owner-entity link, 6/6
- Camera resolution, clean unload
- **World placement** — turned out to need no solving at all (§3f)

Open: the internal ESP draws nothing because **every bone reads 0.00**
(§4). And health is still not found structurally (§5).

---

## 1. Folder map

| folder | what |
|---|---|
| `00_START/` | this file; old indexes in `superseded/` |
| `01_active_decrypter/` | the external decrypter project + **all v1–v5 recon notes** (~10,600 lines) |
| `02_crypto_map/` | crypto map + entity pattern trace |
| `02_ida_dump/` | IDA database, `RainbowSix_dump.exe.i64` (2.7 GB) |
| `03_external_sources/` | UnknownCheats source review |
| `03_rust_dumper_shared/` | Rust-game decrypt code, kept for technique only |
| `04_older_versions/` | prior iterations, preserved |
| `05_reference_cheats/` | paths to downloaded UC repos (not copied, 10 GB) |
| `06_internal_ida/` | **this session's IDA work** — see §2. `SESSION_FINDINGS.md` holds the internal-port results: the pose pointer is returned by GetTransforms (not decrypted), `abstraction = [[character+0x30]+8]`, and the bone-writer buffer is bind-pose data with no world position in it. |

Code projects live outside this tree (they are builds, not research):

| project | where | role |
|---|---|---|
| `Bytecode-Internal` | `Downloads\Bytecode-Internal` | in-process RE tool, HTTP **:9998** |
| `Bytecode` | `Downloads\Reverse Engineering\Unpackers\Bytecode` | external tool, HTTP **:9999**, `/eval` = exact 64-bit math |
| `r6-internal` | `Downloads\r6-internal` | **the internal ESP being built now** |
| `r6-readonly-skeleton` | `Downloads\r6-readonly-skeleton` | reference external ESP — read-only, the thing being replicated |
| `vam` | `Downloads\vam` | emulator-based reference implementation |
| `SiegeSkel` | `Downloads\SiegeSkel` | read-only D3D11+ImGui overlay |

---

## 2. Read in this order

1. **this file**
2. `06_internal_ida/VERIFIED.md` — what survived checking, and what did not
3. `06_internal_ida/BRIEF.md` — API signatures, the base-address trap
4. `06_internal_ida/OBJECTS.md`, `TRANSFORM.md` — object/transform detail
5. `01_active_decrypter/recon_notes/SIEGE_RECON_V5.md` — how the
   decryption was derived (§20–§39), the `vam` architecture (§40–§42)
6. `00_START/superseded/SESSION_HANDOFF.md` — still correct for the
   **crypto templates** and the **crash rules**, nothing else

---

## 3. Verified facts

### 3a. Decryption — all confirmed live

| layer | formula |
|---|---|
| bone buffer ptr | `ROL64(enc,4) − TLS[0x9800]` |
| `r15` source array | `([r10] + 0x78731A5E605CAA6) ^ rdx` |
| prologue records | byte-wise XOR vs `[skel+0xD0]` |
| MBA globals | `mask + index` (4/4 sites) |
| entity chain | `ROL64((f + K1) ^ K2, 45)` |
| `m_BoneIDMap` | `{u32 hash, u16 idx}` stride 8 |

T7 verified in situ at RVA `+0x42EB7D2`.

### 3b. Four obfuscation mechanisms

1. TLS-keyed value crypto
2. MBA identities
3. mask+index addressing
4. stack-hashed key selection — **not externally reproducible**

### 3c. Mask+global call targets resolve OFFLINE

```asm
mov rdx, K1
add rdx, [global]
mov r9,  K2
xor r9,  rdx
call r9            ; target = (K1 + g) ^ K2
```

Proven at `+0x1D41ACE` -> `+0x1D45D50`, lands in `.text`. No emulator, no
live process needed. `06_internal_ida/resolve.py` does this.

**Open:** whether dumped globals equal live ones. One measured global had
a constant high half and a churning low half — so probably per-global.

### 3d. Segment layout — check this before believing any address

```
.text     +00001000 .. +11FAF000   CODE
.rdata    +11FAF000 .. +12BDD000
.data     +12BDD000 .. +14014000
.pdata    +14014000 .. +143FA000
.tls      +14401000 .. +1441E000
.UBX0     +1442E000 .. +145D0000   CODE
.UBX1     +145D0000 .. +1B361000   CODE
```

**`.text` ends at `+0x11FAF000`.** This one check invalidated two agent
findings. `.UBX0`/`.UBX1` are ~110 MB of unexamined executable.

### 3e. The player class

Vtable RVA **`+0x121CBFC8`**, confirmed live. 40 slots; 30 real methods.
`+0x756F0` is shared by 19 vtables — which is why shape-based
identification kept landing on sibling classes.

Slot 37 = the component iterator, `+0x1CE4200`, read in full:
`entity+0xD8` = components array, `entity+0xE0` = count, **used raw** (no
mask in the game's own code). `+0x2D4` cached bool, `+0x2D5` valid flag,
`+0xB8` bit `0x20` gates the path.

### 3f. ⚠️ CORRECTED 2026-09-18 — the bone writer emits BIND POSE

**The claim below is wrong and is kept only so it is not re-derived.**

It said the writer at `+0x42EB7B0..+0x42EB85E` emits finished world-space
affine 4x4s. Measured live across four frames on one owner, while the
player was moving, rows 0-2 of every bone are **byte-identical** and each
is exactly unit length. The 4th row — read as "translation" — changes by
~100 m per frame because it is the next 16 bytes of a fresh scratch
allocation, not part of the matrix.

Frozen orthonormal rows are bind / inverse-bind data. **There is no world
position in that buffer at all.** Both attempted readings of the
translation (`m[3],m[7],m[11]` and then `m[12],m[13],m[14]`) were looking
for something that does not exist there.

Live poses come from `Reflex::GetTransforms` (RVA `+0x41E870`), which
writes the pose-buffer pointer into an out-parameter. See
`06_internal_ida/SESSION_FINDINGS.md`.

The superseded claim:

The "poses are model-space" premise that drove ~6 hours of world-matrix
hunting came from five rigs sharing a root position. That was five idle
players in the same animation frame — a fact about animation, not about
coordinate space. `no_world 0` achieved.

---

## 4. ⚠️ SUPERSEDED — see `06_internal_ida/SESSION_FINDINGS.md`

The "bones read as zeros" problem is resolved and the diagnosis below was
wrong. It is not a stride mismatch: the captured buffer is bind-pose data
(§3f) and contains no position to read at any stride. Bone counts also
come from the DESCRIPTOR (100-300 for an operator), not from the
breakpoint's `max_index`, which was yielding ~32-bone fragments.

The original text, kept for the record:

**Leading hypothesis — stride mismatch.** `r6-internal\src\game\skeleton.hpp`
uses `kBoneStride = 0x40`, `kBoneFloats = 16`. The reference external, at
`r6-readonly-skeleton\src\worker\pose_worker.cpp:443-451`, uses:

```cpp
const auto size   = bone_count        * 0x20;
const auto offset = bone_indices_[j]  * 0x20;
memcpy(out[j].data(), buffer.data() + offset, sizeof(float) * 3);
```

**Stride `0x20`, three floats.**

The ambiguity worth keeping in mind: **both may be real.** The writer I
breakpoint genuinely emits 64-byte matrices; the external reads the *pose
pointer*, a different buffer with 32-byte-stride position vectors. Those
are two buffers, not one contradiction. Next step is the diagnostic in
`dllmain.cpp` that dumps the captured buffer as `0x40` / `0x20` / `0x10`
and lets the data decide — it is written but was never built (the build
failed `LNK1104`, the DLL was still injected; type `unload` first).

---

## 5. Health — still unfound

The claimed answer (`+0x12DD6070`, kind `0x21D`, field `comp+0x15C`) was
**fabricated** — that address is in `.data`, and the quoted disassembly
was data bytes decoded as instructions. Tested live: `+0x15C` read
`-1438943790`, and only 1 of 3 players had the component.

The structural route not yet walked: the player vtable's large methods.

| slot | RVA | size |
|---|---|---|
| 10 | `+0x1D1C780` | 7,235 |
| 29 | `+0x1D39DA0` | 5,827 |
| 3 | `+0x1D41A40` | 4,565 |

---

## 6. Hard rules

**Safety (non-negotiable):**

1. **Read-only.** No `WriteProcessMemory`, no writes to game memory ever.
2. **No hooking.** No Present/swapchain hook, no detours, no trampolines,
   no IAT or vtable patching. The overlay stays a separate layered window.
3. Hardware breakpoints are fine — they read registers and return.

**Method:**

4. **Be structural, not statistical.** Start from an object whose identity
   is measured, read the code that operates on it, follow what it does. A
   400,000-site byte scan produced kind *frequencies*; frequency is not
   structure. It also silently included `.data`, which is how `0x21D` came
   back with 583 sites when the true count in code is 279.
5. **Proximity in memory is not evidence. Content is.** Find candidates
   cheaply, then accept only if content satisfies invariants. This is what
   separated the real bone array (sane 100%, roots 1) from proximity
   candidates (4–45%).
6. **Check the segment before believing any address** (§3d).
7. **Never generalise from one sample.** Five rigs sharing a pose is not a
   coordinate space.

**Crash rules (learned the hard way):**

8. Never return `CONTINUE_SEARCH` from the VEH for a trap your own debug
   registers caused.
9. Never suspend game threads to install debug registers.
10. Validate before dereferencing inside a VEH. A fault there kills the
    process with **no event-log record at all**.
11. Pick a **free** DR slot per thread. Hardcoding DR0 silently steals
    Bytecode-Internal's breakpoint.
12. Order teardown correctly: disarm **then** clear the handler. The
    reverse leaves threads armed with an unrecognising handler.
13. The HTTP server must handle each client on its own thread.

**Environment:**

14. **PowerShell mangles unsigned 64-bit math and hex literals.** Use the
    external tool's `/eval` (JavaScript BigInt) for arithmetic.
15. **Never call `auto_wait()` over the IDA MCP** — it blocks the
    transport until analysis settles, and the call times out.
16. Heredoc `\n` mangling breaks C string literals. `r6-internal\fixnl.py`
    repairs it.

---

## 7. ⚠️ The base-address trap

**Always exchange RVAs, never absolutes.** The IDA dump base and the live
base differ every launch; absolute addresses fail *silently*.

The dumps on disk:

| file | imagebase | image size |
|---|---|---|
| `02_ida_dump\RainbowSix_dump.exe` | `0x7FF6FBEB0000` | `0x187DE000` |
| `Game Cheats\...\r6 dumper\RainbowSix_dump.exe` | `0x7FF6516E0000` | `0x19DC5000` |

⚠️ **The RVAs in `06_internal_ida/` were derived against a database
reporting base `0x7FF743770000` — which is neither of these.** That was a
third dump, loaded in the IDA MCP session, and it is not in this tree.
Before reusing any `+0x...` from those files, confirm the loaded
database's base first, or the addresses are meaningless.

---

## 8. Tooling

| thing | where |
|---|---|
| IDA MCP | `http://127.0.0.1:13337/mcp` (`ida-pro`; the `ida` entry was repointed from the dead `:13338`) |
| internal tool | `Bytecode-Internal`, **:9998** |
| external tool | `Bytecode`, **:9999** — `/eval` for exact math |
| IDA helper scripts | `06_internal_ida/*.py` |

Rebuild + reinject loop, no game restart:

```
POST /unload  ->  cmake --build build --config Release  ->  Inject.exe
```

Performance: `/bones` per frame = **2 fps** (each call arms a breakpoint
and waits out its timeout). `/stream` = **158 fps**. Always `/stream`.

---

## 9. Claims that did NOT survive — keep them dead

| claim | why it is wrong |
|---|---|
| health at `+0x12DD6070` | in `.data`; "disassembly" was decoded data |
| player ctor at `+0x1CA1BF0` | it is a byte-stream deserialiser |
| skeleton vtable has 66 methods | 5 slots; 61 were walked past the end |
| `entity+0x50` = map origin | translation row of an **ungated** matrix — the `+0x5E` flag was never checked |
| score-150 `GetTransform` | zero xrefs, vtable-only, wrong class family |
| the transcribed 4-hop chain | wrong constants, 3 hops not 4, per-site key slot |
| count mask `& 0x3FFFFFFF` | `& 0x1FFFFFFF` (29-bit) — and the game uses it **raw** |
| "41 bone writers" | 5 sites, 1 executing |
| 99-bone vs 32-bone rigs need a remap | different bone sets; no remap exists |
| `TLS[0x98C8]` "not a key" | it **is** an add-key, load-bearing |
| "poses are model-space" | the palette is already world-composed (§3f) |

Most V4 signatures and all T1 constants are **dead in the current build**.

---

## 10. Next steps

1. `unload`, rebuild `r6-internal`, run the stride diagnostic, fix the
   bone stride (§4).
2. Health via the player vtable's large methods (§5).
3. The 3,000+ line decrypter tool — the stated goal of the IDA research.
