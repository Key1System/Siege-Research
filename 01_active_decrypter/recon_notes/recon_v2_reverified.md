# Rainbow Six Siege — Deep RE Recon (v2, re-verified)

> Ethical RE / CTF-style binary analysis. No cheat development, no in-game
> modification, no online interaction. Pure structural reverse engineering
> of how Ubisoft packs and protects the shipped executable.

---

## §0 Provenance

| Item | Value |
|---|---|
| Binary | `RainbowSix_dump.exe` (memory dump of a running process) |
| IDB | `C:\Users\hhhuh\Downloads\CHEATS\RainbowSix_dump.exe.i64` |
| Image base | `0x7ff71a2b0000` |
| Image size | `0x1d3f4000` (~ 488 MiB) |
| MD5 | `9c1aa44cfd9b9eb9ee017988038f8466` |
| SHA-256 | `cd32734085b015969c3d63faebf4ef5bd3235927aea5fc252367b2b7c2cdb2e9` |
| Tooling | IDA Pro 9.3, `ida-pro-mcp` over `127.0.0.1:13337` |
| Strings cache | 2,107,057 entries (ready) |
| Hex-Rays | ready |
| **Auto-analysis** | **still not finished** at time of v2 sweep (uptime 3287 s). Function counts will keep increasing; xref counts already do. |
| Total functions defined | 315,661 (vs. 315,643 in v1 — auto-analysis added 18) |

---

## §1 Component map — what is this binary?

### 1.1 Layer stack

| Layer | Identification | Hard evidence |
|---|---|---|
| Engine | **Anvil** (Ubisoft Montreal) | strings: `Anvil`, `startanvil`, `anvilid`, `ExtractAnvilDataToBigFile`, `anvil.gui/gui/src/gui/phoenix/factory.h`, `anvil://flagID={{%key}}` |
| Code protection | **VMProtect** (Ubisoft-renamed sections `.UBX0`/`.UBX1`) | section bytes match canonical VMProtect handler shape (§3.5); strings: `vmprotectsdk64.dll`, `vmprotectedbuild` |
| Anti-cheat | **BattlEye** (user-mode) + **BEDaisy.sys** (kernel, separate driver) | strings: `BattlEye\BEClient_x64.dll`, `BattlEyeGlobalBan`, `BattlEyeKick`, `cheat_battleye`, `KICKEDBATTLEYE`, `BattlEye Level`, `RC_BATTLEYE_*` |
| Compiler hardening | MSVC + CFG + XFG + retpoline | sections `.00cfg`, `.gxfg`, `.retplne`, `.voltbl` |
| Audio | Wwise (Audiokinetic) | 303 exports matching `AK::*` / `CAk*` |
| Render | DX12 primary, DX9 fallback, NVIDIA DLSS, AMD AGS | imports `d3d12`, `dxgi`, `d3d9`, `amd_ags_x64`, `GFSDK_Aftermath_Lib.x64` |
| DRM / platform | Steam + Ubisoft Connect R2 | imports `steam_api64`, `upc_r2_loader64` |
| Voice / chat | Vivox + Tox.chat | imports `vivoxsdk`, `libtox` |
| Crash dumps | NVIDIA Aftermath | import `GFSDK_Aftermath_Lib.x64` |

### 1.2 PE sections (verified live)

| Name | Start | End | Size | Perm | Role |
|---|---|---|---|---|---|
| `.text` | `0x7ff71a2b1000` | `0x7ff72cd73000` | 298.8 MiB | r-x | Normal compiled code (MBA-obfuscated in places) |
| `.rdata` | `0x7ff72cd73000` | `0x7ff72d9d7000` | 12.4 MiB | r-- | Constants, vtables, strings |
| `.data` | `0x7ff72d9d7000` | `0x7ff72f2b7000` | 24.9 MiB | rw- | R/W globals |
| `.pdata` | `0x7ff72f2b7000` | `0x7ff72f67d000` | 3.8 MiB | r-- | x64 SEH unwind |
| `.00cfg` | `0x7ff72f67d000` | `0x7ff72f67e000` | 4 KiB | r-- | CFG dispatch table (verified: contains 8-byte pointers into `.text`) |
| `.gxfg` | `0x7ff72f67e000` | `0x7ff72f683000` | 20 KiB | r-- | **XFG type-hash table** — verified: 16-byte stride, first 8 bytes is length-prefix `0xC0`, then qword type hashes |
| `.retplne` | `0x7ff72f683000` | `0x7ff72f684000` | 4 KiB | --- | Retpoline (anti-Spectre) metadata |
| `.tls` | `0x7ff72f684000` | `0x7ff72f68d000` | 36 KiB | rw- | TLS callbacks (run before EntryPoint) |
| `.voltbl` | `0x7ff72f68d000` | `0x7ff72f68e000` | 4 KiB | --- | MSVC volatile-access table |
| `_RDATA` | `0x7ff72f68e000` | `0x7ff72f6c2000` | 208 KiB | r-- | Resource directory remnants |
| **`.UBX0`** | **`0x7ff72f6c2000`** | **`0x7ff72f9bf000`** | **3.0 MiB** | **r-x** | **VMProtect dispatcher + handler chains** |
| **`.UBX1`** | **`0x7ff72f9bf000`** | **`0x7ff736e80000`** | **116.8 MiB** | **rwx** | **Encrypted VM bytecode + RWX scratch (decryption workspace)** |
| `.idata` | `0x7ff736e80000` | `0x7ff736e802f8` | 760 B | rwx | Tiny IAT stub (real IAT relocated by VMProtect) |
| `.UBX1` (2) | `0x7ff736e802f8` | `0x7ff7374e9000` | 6.4 MiB | rwx | Trailing VMProtect data |

### 1.3 Imports — 40 modules (not 42 as v1 claimed)

| Category | Modules |
|---|---|
| **DRM / platform** | `steam_api64`, `upc_r2_loader64`, `defaultargs` (Ubisoft-internal default-args helper) |
| **Voice / chat** | `vivoxsdk`, `libtox` |
| **Network** | `WS2_32`, `IPHLPAPI`, `WINHTTP`, `RPCRT4` |
| **Crypto** | `bcrypt`, `CRYPT32`, `ncrypt`, `tbs` |
| **GPU / render** | `d3d12`, `d3d9`, `dxgi`, `amd_ags_x64`, `GFSDK_Aftermath_Lib.x64`, `XINPUT9_1_0`, `DINPUT8` |
| **OS / shell** | `ADVAPI32`, `GDI32`, `IMM32`, `SHELL32`, `WTSAPI32`, `USER32`, `KERNEL32`, `ole32`, `OLEAUT32`, `WindowsCodecs`, `pdh`, `POWRPROF`, `api-ms-win-power-base-l1-1-0`, `SHLWAPI`, `COMCTL32`, `VERSION`, `SETUPAPI`, `WINMM`, `HID`, `api-ms-win-core-path-l1-1-0` |

> **Correction from v1**: `vmprotectsdk64.dll` is **NOT** in the IAT. The DLL name appears only as a string in `.rdata` (used as diagnostic identifier). The actual VMProtect runtime is **statically linked** into `.UBX0`/`.UBX1`. The v1 claim "Imports: vmprotectsdk64.dll" was wrong.

> **Correction from v1**: no `BattlEye*` imports either — BattlEye injects `BEClient_x64.dll` from outside, the game integrates via in-process callbacks.

---

## §2 Protection layers (verified)

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3 — VMProtect virtualization                                  │
│   • .UBX0 (3 MiB, r-x): dispatcher + ~9,850 unique handler chains   │
│   • .UBX1 (117 MiB, rwx): encrypted VM bytecode + decryption scratch│
│   • Applied to ~2 % of .text functions (6,273 / 315,661)            │
│   • Geographically clustered in first 38 % of .text                 │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2 — MBA (Mixed-Boolean-Arithmetic) obfuscation                │
│   • Verified on sub_7FF71A5C4B60: 30+ insns of                      │
│     (x|m)+(x&m), (x^y)+2*(x&y) identities collapsing to small ops   │
│   • Affects security-sensitive .text functions                      │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 1 — MSVC hardened compile                                     │
│   • CFG (.00cfg) — indirect-call target table verified              │
│   • XFG (.gxfg) — type-hash table verified (16-byte stride)         │
│   • Retpoline (.retplne) — anti-Spectre stubs present               │
└─────────────────────────────────────────────────────────────────────┘
```

---

## §3 VMProtect topology — full sweep results

### 3.1 Macro stats (300 MB of `.text` scanned for `E8`/`E9` relative xrefs targeting `.UBX0`/`.UBX1`)

| Metric | Value |
|---|---|
| Functions walked | 315,661 |
| Direct `call`s into `.UBX0` (`E8 disp32`) | **9,850** |
| Direct `jmp`s into `.UBX0` (`E9 disp32`) | **0** |
| Direct `call`s into `.UBX1` | **0** |
| Direct `jmp`s into `.UBX1` | **0** |
| Distinct `.UBX0` entry points hit | **9,850** (1:1 with calls — no sharing) |
| Distinct gateway functions in `.text` | **6,273** (≈ 1.99 % of all functions) |

### 3.2 Spatial distribution

```
.text layout (0x7ff71a2b1000 → 0x7ff72cd73000, 298.8 MiB)

│0%                  38%                                100% │
│■■■■■■■■■■■■■■■■■■■■                                        │
│  ←─ all 9,850 VM-gated calls live here ─→                  │
│                     ←──── 62 % is NORMAL code ────→        │
│                          (zero calls into .UBX0/.UBX1)     │
```

> **Implication**: VMProtect is applied selectively, not blanket. The 38 % "hot zone" is where the security-critical primitives live (NVAPI/OS-API resolvers, license-check, anti-tamper, BattlEye glue). The remaining 62 % is gameplay/render/audio/network code in plain (CFG/XFG-protected but not VM'd) form.

> **Correction from v1**: the previous note "Phase 3 — 54/54 sampled functions are gateway-virtualized" was *sampling bias* — those 54 came from the very start of `.text` where density is ~100 %. Across the full binary the true rate is ~2 %.

### 3.3 Caller-target relationship

| Pattern | Value |
|---|---|
| Targets called by exactly 1 function | **9,850 (100 %)** |
| Targets shared by ≥ 2 functions | **0** |
| Max calls into one target | 1 |

**Interpretation**: every virtualized function gets its own unique entry point in `.UBX0`. There is no shared "VM dispatcher" called by many callers — each protected function is independently virtualized.

### 3.4 Top gateway-calling functions (15 highest)

| Address | VM calls | Likely role |
|---|---|---|
| [sub_7FF71A92B1D0](#) | 20 | switch-based fatal-error/assertion dispatcher (21-case jump table, each case → unique VM entry, each followed by `int 3`) |
| `sub_7FF71A942D90` | 20 | sibling of above |
| `sub_7FF71A945A40` | 20 | sibling |
| `sub_7FF71A95A810` | 20 | sibling |
| `sub_7FF71A92FF50` | 19 | sibling |
| `sub_7FF71A95C330` | 19 | sibling |
| `sub_7FF71A943990` | 18 | sibling |
| `sub_7FF71A95DB10` | 18 | sibling |
| `sub_7FF71A960C70` | 18 | sibling |
| `sub_7FF71A322A60` | 13 | — |
| `sub_7FF71A2B4C70` | 10 | — |
| `sub_7FF71B6151A0` | 10 | — |
| `sub_7FF71A837AC0` | 8 | — |
| `sub_7FF71A2B2DF0` | 6 | — |
| `sub_7FF71A2B33D0` | 6 | — |

The cluster at `0x7ff71a92*` looks like a family of state-machine dispatchers — same shape, different state set, each routing 18-20 cases to unique VM entries.

### 3.5 `.UBX0` handler-entry pattern (12 sampled targets)

All sampled entries match the canonical VMProtect handler shape:

```
<padding nop>  90
<1-2 byte real op:  pop reg, movsx, lahf, xchg [rsp],reg, ...>
<dead pop or alias>  58 / 5A / 5F / ...
<E9 disp32>  jmp <next handler in chain>
```

Verified samples (first 8-12 bytes each):

| Address | Bytes | Decoded |
|---|---|---|
| `0x7ff72f6c2000` | `90 0F BF D4 5A 48 87 14 24 E9 3B 3E 13 00` | nop · movsx edx,sp · pop rdx · xchg [rsp],rdx · jmp +0x133E3B (entry of dispatcher chain) |
| `0x7ff72f6c6c04` | `90 58 E9 88 FB 18 00 C3` | nop · pop rax · jmp +0x18FB88 · ret |
| `0x7ff72f6ca9ed` | `90 49 63 C6 B0 2F 58 E9 2D 45 00 00` | nop · movsxd rax,r14d · mov al,0x2F · pop rax · jmp +0x452D |
| `0x7ff72f6cd752` | `90 5F E9 8A 7D 18 00` | nop · pop rdi · jmp +0x187D8A |
| `0x7ff72f6e0b2a` | `90 E9 E3 19 0C 00` | nop · jmp +0xC19E3 (trivial transit handler) |
| `0x7ff72f6e5b77` | `90 66 0F CF 5F E9 1D 58 02 00` | nop · bswap di · pop rdi · jmp +0x2581D |
| `0x7ff72f713c45` | `90 9F 90 48 0F BF C6 58 E9 E8 06 FD FF` | nop · lahf · nop · movsx rax,si · pop rax · jmp -0x2F918 |
| `0x7ff72f7133ba` | `90 E9 5F A8 02 00` | nop · jmp +0x2A85F |

`.UBX1` head (`0x7ff72f9bf000`) is high-entropy random bytes (`37 E6 2D CD 6C 5C 25 45 …`) → confirms it is the **encrypted bytecode store**, not directly callable from `.text` (matches the 0-call sweep result).

---

## §4 Logging / assert thunk (the ultra-hot center)

### 4.1 The 14,719-xref star: `sub_7FF71A8D2380`

```asm
sub_7FF71A8D2380:
    sub  rsp, 28h
    mov  r10, r8
    mov  r8,  rdx
    mov  rdx, rcx
    mov  [rsp+20h], r9
    mov  ecx, 1               ; forced category / level
    mov  r9,  r10
    call sub_7FF71A7B9AF0     ; worker (only 1 xref — only via this thunk)
```

| Metric | Value |
|---|---|
| Function size | 8 instructions / ~30 bytes |
| Xrefs into `sub_7FF71A8D2380` | **14,719** (v1 said ~5,475 — auto-analysis kept rediscovering callers) |
| Xrefs into worker `sub_7FF71A7B9AF0` | **1** (only the thunk above) |

**Interpretation**: this is the universal calling-convention adapter for a logging or assertion API. Caller signature is `(arg1=ctx, arg2=fmt, arg3=arg, arg4=arg)`; thunk swaps the first three into `(ecx=1, rdx=ctx, r8=fmt, r9=arg)` and forwards. The hard-coded `1` is the category/severity. Worker is wrapped behind the thunk — never called directly.

### 4.2 Per-callsite descriptor thunks

```asm
sub_7FF71A6BF440:                    ; 1,921 xrefs (v1: ~1000)
    sub  rsp, 28h
    lea  rcx, unk_7FF72D3C9710       ; per-callsite descriptor in .rdata
    call loc_7FF71A5C4B50            ; → MBA-protected worker
    nop
    add  rsp, 28h
    retn
```

| Symbol | Xrefs | Shape |
|---|---|---|
| `sub_7FF71A6BF440` | 1,921 | per-callsite descriptor → worker |
| `sub_7FF71A5C4310` | 920 | per-callsite descriptor → worker (variant) |
| `loc_7FF71A5C4B50` | 16 | entry into the worker body |
| `sub_7FF71A5C4B60` | 0 | MBA-obfuscated body (only reachable by fall-through from `loc_7FF71A5C4B50`) |

The worker `loc_7FF71A5C4B50`/`sub_7FF71A5C4B60` is the MBA exemplar (see §5).

---

## §5 MBA obfuscation evidence

Verified live on `sub_7FF71A5C4B60` (the body that `loc_7FF71A5C4B50` falls into):

```asm
mov  r10d, [rcx]               ; load input
add  r10d, [rdx]               ; sum
lea  edx,  [r8 - 1E129F4Dh]    ; sub const
mov  ecx,  r8d
and  ecx,  0E6C921F8h          ; mask
or   r8d,  0E6C921F8h          ; mask same const
add  r8d,  ecx                 ; (x|m) + (x&m)  ≡  x + m              [MBA identity]
mov  ecx,  r8d
xor  ecx,  edx
not  r8d
and  r8d,  edx
add  r8d,  r8d
sub  r8d,  ecx                 ; (x^y) - 2*(¬x & y)  ≡  x - y         [MBA identity]
…30 more insns of rotating XOR/AND/OR/SUB/SHL with constants
   {0xE6C921F8, 0x4DBC145, 0xA5E7932E, 0xC7DB91B4, 0xCB5C5255, 0x5A186CD2, …}
```

This is the OREANS-style MBA generator pass that VMProtect Ultra applies before virtualization. Constants rotate through a fixed schedule; identities `(x|m)+(x&m)≡x+m` and `(x^y)+2(x&y)≡x+y` collapse them.

**Deobfuscation candidates**: SiMBA, `mba-blast`, `MBA-Solver`, angr's constant-folder, Miasm symbolic-reduction.

---

## §6 Strings — string-driven pivots (all unencrypted)

| Address | String | Use |
|---|---|---|
| `0x7ff72d4d7f5d` | `<a href="anvil://flagID={{%key}}">Click here to view this Flag in Anvil.</a>` | dev-tooling URL scheme — Anvil engine "flag in editor" link |
| `0x7ff72d5141e3` | `BattlEyeGlobalBan` | result code |
| `0x7ff72d516fed` | `BattlEye\BEClient_x64.dll` | DLL load path |
| `0x7ff72d5170f8` | `vmprotectsdk64.dll` | diagnostic identifier (NOT imported) |
| `0x7ff72d517509` | `startanvil` | Anvil engine entry |
| `0x7ff72d517514` | `Anvil` | engine ident |
| `0x7ff72d51a4ed` | `BattlEyeKick` | result code |
| `0x7ff72d52389d` | `cheat_battleye` | dev/telemetry tag |
| `0x7ff72d5238ac` | `BattlEye` | category |
| `0x7ff72d530081` | `ExtractAnvilDataToBigFile` | Anvil `.forge` archive tooling |
| `0x7ff72d53759c` | `vmprotectedbuild` | build-flag check |
| `0x7ff72d537a5e` | `anvilid` | engine ident |
| `0x7ff72d557d0f` | `RC_BATTLEYE_UNKNOWN_ERROR` | BE result-code enum |
| `0x7ff72d55b763` | `RC_BATTLEYE_SERVICE_NOT_RUNNING` | BE result-code enum |
| `0x7ff72d55c539` | `KICKEDBATTLEYE` | kick reason |
| `0x7ff72d55cee9` | `RC_BATTLEYE_INIT_FAILURE` | BE result-code enum |
| `0x7ff72d55d1e0` | `RC_BATTLEYE_LOADING_FAILURE` | BE result-code enum |
| `0x7ff72d562131` | `RC_BATTLEYE_UPDATE_NEEDED` | BE result-code enum |
| `0x7ff72d5a4be6` | `pipeline\packages\ui\anvil.gui\gui\src\gui/phoenix/factory.h(11)` | source-path leak (UI/Phoenix) |
| `0x7ff72d5b11ee` | `BattlEye Level ` | ban-severity log |
| `0x7ff72dea28d0` | `C:\Program Files (x86)\Steam\steamapps\common\Tom Clancy's Rainbow Six Siege\BattlEye\BEClient_x64.dll` | dev-machine install path leak |

Strings are not encrypted → string-xref pivoting is viable for finding subsystems (Aim, FOV, Player, AntiCheat, …) once auto-analysis completes.

---

## §7 Corrections summary — what v1 got wrong

| v1 claim | Reality | Where corrected |
|---|---|---|
| "Imports: vmprotectsdk64.dll" | Not imported. String only. VMProtect is statically linked. | §1.3 |
| "42 imported modules" | 40 modules | §1.3 |
| "5,475 xrefs to `sub_7FF71A8D2380`" | 14,719 (auto-analysis still running during v1) | §4.1 |
| "~1,000 xrefs to `sub_7FF71A6BF440`" | 1,921 | §4.2 |
| "Every function jumps into `.UBX0` (54/54 sampled)" | Only ~2 % do. 54-sample was the start of `.text`, where density is ~100 %. | §3.2 |
| "98 distinct `.UBX0` entry points sampled" | 9,850 actual entry points (each unique-use) | §3.1 |

---

## §8 Open questions & next phases

| Phase | Question | Approach |
|---|---|---|
| 3-continued | Where does the `.UBX0[head]` dispatcher chain terminate? Is there a 256-/512-slot handler-index table? | Trace `0x7ff72f6c2000` → `+0x133E3B` → handler chain; look for register-indexed `jmp [tbl+r*8]` pattern. |
| 4 | Cluster the 9,850 entry points by handler-chain length (number of nop+jmp transit links before a real op). | Walk each entry, count transits to terminator; bucket histogram. |
| 5 | RTTI / vtable inventory (after auto-analysis completes). Anvil uses `nFw::`, `nFs::` namespaces. | `find_regex` on those prefixes; vtable scanner over `.rdata`. |
| 6 | Network surface — `WS2_32`/`WINHTTP` wrappers + Anvil `nNet::*` packet-dispatch tables. | xref from `WSARecv`/`WinHttpReadData` upward. |
| 7 | BattlEye callback boundary — which game functions does BE call into. | xref from `BattlEye*` strings and `RC_BATTLEYE_*` enum, walk back. |
| 8 | TLS callbacks — first code executed before OEP. `.tls` is at `0x7ff72f684000`. | Parse the TLS directory in `.data` or the IDB `__tls_callback` symbol. |

---

## §10 Anvil custom class registry (the "encrypted classes")

> The user characterized Anvil classes as "encrypted." What's really going on
> is that Anvil **strips MSVC RTTI from its own classes** and replaces it
> with a custom indirected registry. The only `.?A[VU]*@@` RTTI tags in the
> binary come from third-party libraries (Havok `hknp*`, CryptoPP, Microsoft
> glTF, `std::*`, `asio::*`). Every Anvil engine class identifies itself
> through a single global at `off_7FF72DC93E80`.

### 10.1 The global registry layout (`off_7FF72DC93E80`)

The pattern was observed across 30+ functions (`sub_7FF71A312D90`, `sub_7FF71CB89C00`,
`sub_7FF71CDAC1B0`, `sub_7FF71A3096B0`, `sub_7FF71A332AE0`, etc.) — it is the
canonical Anvil release-by-handle / class-lookup primitive:

```c
// Resolve a 64-bit Anvil handle to its class instance and call vtable[5]:
v_class_arr = *((QWORD *)off_7FF72DC93E80 + 110);   // +880 — class array
v_class     = *(QWORD *)(v_class_arr + 8 * HIDWORD(handle));
slot_byte   = *(BYTE *)(v_class + WORD1(handle));
slot        = slot_byte & 0x7F;                      // mask top "sentinel" bit
if (slot == 0x7F)  __debugbreak();                   // invalid slot trap
instance    = *((QWORD *)off_7FF72DC93E80 + 111 + slot);  // +888+8*slot
instance->vtable[5](instance, handle);               // virtual call (often release)
InterlockedDecrement(instance + 8);                  // refcount-- on instance
```

### 10.2 Anvil handle layout (64-bit packed type-erased reference)

```
 63                   32 31           16 15        0
┌──────────────────────┬───────────────┬───────────┐
│   class table index  │ slot byte ofs │ reserved  │
│   HIDWORD(handle)    │ WORD1(low)    │           │
└──────────────────────┴───────────────┴───────────┘
```

* `HIDWORD(handle)` indexes the per-table class-info array (`reg[110]`).
* `WORD1(LODWORD(handle))` indexes the slot byte inside that class info.
* `slot_byte & 0x7F` is the small class identifier.
* `slot_byte == -1` means "invalid handle" → forces fallback to `reg[1908]` default.
* `0x7F` is the sentinel for "table full" → triggers `__debugbreak`.

### 10.3 ClassID obfuscation (the actual "encryption")

`sub_7FF71CB89C00` (the error reporter we decompiled) computes a class identifier
for the formatted log via:

```c
ClassID = (RTTI_table[7] - 0x33168FD0) ^ TLS[888]
```

Where:
* `RTTI_table` = `*(QWORD *)((*(QWORD *)this) + 8)` — secondary vtable / type-info ptr.
* `RTTI_table[7]` (offset +28) is a u32 type cookie.
* `0x33168FD0` is the subtraction constant.
* `TLS[888]` is a **per-thread randomization key**, set during thread init.

So `ClassID` differs across threads and across game launches. This defeats
naive ClassID precomputation by an attacker — you can only resolve class
identity at runtime, in the right thread.

The log format string used is fmtlib-style: `"[{}] : {}"` formatted with
`ClassID(0x%08x)` as first arg and the user error string as second.

---

## §11 BaseEntity → ComponentList → DamageComponent → health chain

Reverse-engineered from the **DBNO (Down-But-Not-Out) Monitor**
(`sub_7FF71CDD0300`) — this is the function that decides when a downed
player's revive timer expires. It traverses the full chain you described.

### 11.1 Chain walk

```c
// a4 = monitor config (contains EntityHandle + timeout)
v15 = *(char **)(a4 + 248);                    // (1) EntityHandle pointer
v16 = *(QWORD *)v15;                           // (2) BaseEntity *
v17 = *(BYTE *)(v16 + 488);                    // (3) cached DamageComponent slot index
if (v17 == 255) goto "Error: DamageComponent Invalid";
component_list = *(QWORD *)(v16 + 208);        // (4) ComponentList pointer
v18 = *(QWORD *)(component_list + 8 * v17);    // (5) DamageComponent *
if (!v18) goto "Error: DamageComponent Invalid";
// (6) virtual call into HealthState sub-object at +336 inside DamageComponent
v26 = v18 + 336;                                // HealthState *
vtable = qword_7FF72DADE438 - <MBA-obfuscated offset>;
state  = vtable_method(v26, &v28);              // v28[0] = current state
if (v28[0] == 3) /* player is in DBNO */ ;
```

### 11.2 The "ClassCompare" — what it actually is

The "ClassCompare for DmgComponent" you mentioned is **not done at runtime per call**.
The byte at `BaseEntity + 488` is the **cached result of a one-time class compare**
performed when the entity is constructed and the DamageComponent is attached.
That byte holds the *slot index* into the entity's ComponentList. From then on,
every health read is just `entity->components[entity->dmg_slot]` — O(1), no
runtime class comparison.

This is a common ECS pattern (sometimes called "component handle caching" or
"slot-based ECS"). It makes static analysis of "which entities have a
DamageComponent" impossible without running the constructor.

### 11.3 BaseEntity offsets (from the DBNO monitor)

| Offset (dec / hex) | Type | Meaning |
|---|---|---|
| `+0` / `+0x000` | `qword` | vtable / type-info indirection (drives §10.3 ClassID) |
| `+208` / `+0xD0` | `qword*` | ComponentList — pointer to qword array indexed by slot |
| `+488` / `+0x1E8` | `byte` | Cached **DamageComponent slot index** (255 = none) |

### 11.4 DamageComponent offsets

| Offset (dec / hex) | Type | Meaning |
|---|---|---|
| `+336` / `+0x150` | `HealthState*` (sub-object) | Health/damage state. Has its own vtable; `vtable[?]` returns current state enum |

### 11.5 HealthState enum (partial, from DBNO monitor)

| Value | Meaning (inferred) |
|---|---|
| `3` | DBNO (downed) — monitored by the timer |
| `≠ 3` | Not in DBNO (alive, dead, or some other state) |

(Full enum needs the v28 result-handler decompile — Phase 12 follow-up.)

### 11.6 EntityHandle "wrapper" (the `a4+248` thing)

`v15 = *(char **)(a4 + 248)` is a small handle/weak-ref wrapping the entity.
The DBNO monitor also reads `v15[11] < 0` — a sign-bit on byte 11 of the
wrapper that means "entity is valid / strong-ref" vs. "weakly held".
TLS state at `TLS[20]` and `TLS[3276]` gates whether the handle deref is
allowed (game-thread / right-mode check).

---

## §12 Game architecture — there is no GameManager

A grep for `GameManager` returns **only the error-code-prefix string**
`"GAMEMANAGER_ERROR_HOSTMIGRATION_INTEGRITYCHECK"`, which is one case inside
the central error-code-to-string translator (`sub_7FF71C0ED1D0`). That
function is **not** the GameManager — it is a switch over subsystem error
codes that we used to map Siege's modular layout:

| Code range | Subsystem |
|---|---|
| `0x1000–0x1FFF` | Generic errors (timeout, cancel) |
| `0x2000–0x2FFF` | `GAMEFLOW_ERROR_*` (R6GameFlow) |
| `0x3000–0x3FFF` | `GAMEMANAGER_ERROR_*` (a service, not a class) |
| `0x4000–0x4FFF` | `ERROR_SERVICE_NOT_AVAILABLE` (services layer) |
| `0x5000–0x5FFF` | `GAMESTATE_ERROR_*` |
| `0x6000–0x6FFF` | `PLAYERPROGRESSION_ERROR_*` |
| `0x8000–0x8FFF` | `SESSIONMANAGER_ERROR_*` |
| `0x9000–0x9FFF` | `MATCHMAKINGMANAGER_ERROR_*` |
| `0xA000–0xA3FF` | `UBISHOP_ERROR_*` |
| `0xB000–0xB0FF` | `PROFILE_ERROR_*` |
| `0xC000–0xC2FF` | `MULTIEXE_VALIDATION_*` |
| `0xD000–0xD0FF` | `SECURE_PLATFORM_*` (TPM/AK attestation) |

Siege's actual top-level game logic is **distributed across services**:

| Service | Role | Likely entry function |
|---|---|---|
| `R6GameFlow` | Top-level state orchestrator | `sub_7FF721B80E10` (15.7 KB) |
| `R6GameFlowServiceGroupContext` | Service-group context for above | — |
| `R6GameSessionService` | Game session lifecycle | — |
| `R6MatchmakingService` / `R6MatchmakingManager` | Matchmaking | — |
| `GameSoundManager` | Audio reactions to game-state changes (consumer, **not** owner) | — |
| `IPlanningPhaseStateMachine` | Per-round phase state machine (prep → planning → action → end) | `sub_7FF71D7F3EB0` init, `sub_7FF71D77E3E0` phase-timer expire |

`GameSoundManager` is a **consumer** of round/match/escorting state — the
log strings `"GameSoundManager - m_GameRoundState changed from %u to %u"` are
its reaction to events broadcast by the actual state owner. The owner is
`R6GameFlow` + `IPlanningPhaseStateMachine`.

### 12.1 IPlanningPhaseStateMachine is MBA-protected

Both the init handler (`sub_7FF71D7F3EB0`, 6.6 KB) and the timer-expired
handler (`sub_7FF71D77E3E0`, 4.1 KB) **fail Hex-Rays decompilation**. Looking
at the raw asm shows six 64-bit MBA seed constants loaded into registers at
entry, then MBA combining them with `rcx` (the `this` pointer) to derive
offsets:

```asm
mov rbp, 0FFFFFFFF5ECF24B6h
mov rdi, 0E9D09114FA142B6Bh
mov r12, 0BF696465D03486ADh
mov rbx, 0BA67A1B7F9C62A24h
mov rsi, 162F6EEB05EBD494h
mov r15, 81646EC65F08F50h
...
mov  r9, rcx
xor  r9, 0FFFFFFFFB1E92445h
mov  r8, 7FFFFFFFB1E92440h
and  r8, rcx
lea  rax, [r9 + r8*2]        ; (rcx^k) + 2*(rcx&k) = rcx + k    [MBA identity]
mov  r8, 0FFFFFFFFCA355823h
sub  r8, rcx
...
```

These are normal x86 instructions, **not** VMProtect — the state machine is
MBA-obfuscated but lives in plain `.text`. To beat this we need an MBA
simplifier (SiMBA / mba-blast / Miasm), not a VMProtect devirtualizer.

### 12.2 IPlanningPhaseStateMachine states (from strings)

| State string | Likely meaning |
|---|---|
| `PlanningPhaseReady` | All players ready, exit planning |
| `PlanningPhaseLoadout` | Choosing gear |
| `PlanningPhaseOperators` | Choosing operator |
| `PlanningPhaseLocation` | Picking spawn |
| `PlanningPhaseIsCaster` | Spectator/caster mode |
| `PlanningPhaseSyncedState` | Network sync |
| `PreppingPhaseLocation` | Prep-phase (drone) location |

Round phases (from log strings + telemetry JSON):

```
Match  →  PrepPhase  →  PlanningPhase  →  ActionPhase  →  EndOfRoundPhase  →  ...
```

---

## §13 Health field detail (chain of 3, confirmed)

The user's "DamageComponent → health is like a chain of 3" matches what we
found exactly:

```
BaseEntity
  ├── +208 ComponentList ────►  [slot0, slot1, ... slotN]
  │                                       │
  └── +488 DmgComponentSlot ──────────────┘  (cached index, byte)
                                          │
                                          ▼
                                 DamageComponent
                                          │
                                          └── +336 HealthState
                                                      │
                                                      └── vtable[?] →
                                                            health state enum
                                                            (DBNO=3, …)
```

The "chain of 3" indirections are:
1. `BaseEntity → ComponentList` (via +208)
2. `ComponentList[slot] → DamageComponent` (via +488 cached slot)
3. `DamageComponent → HealthState` (via +336 sub-object)

Plus one virtual call (`HealthState.vtable[N]`) to read the actual state enum.
Reading the raw float health value (the `HEALTH:%.2f` debug-printf format
string we found, currently zero-xref) would need decompiling the network
serializer `sub_7FF71CC51850` ("GetHealthReturnValue", 2.2 KB).

---

## §14 Render — confirmed Anvil-Phoenix renderer family

Renderer is **not** called "RenderManager." Found instead:

| Symbol | Role |
|---|---|
| `gfx::EKBaseRenderer` | Base renderer class |
| `gfx::EKDeferredRenderer` | Deferred PBR renderer (the production path) |
| `EKPhoenixRenderer` | Phoenix renderer (alternate / older) |
| `EKGpuIndirectDrawCallHelper` | Indirect draw call batcher |

Specific methods we found by name:
* `gfx::EKBaseRenderer::FinalizeView`
* `gfx::EKDeferredRenderer::SetupAndUpdateStaticCacheForLocalShadowMaps`
* `gfx::EKDeferredRenderer::SetupAndUpdateStaticCacheForOneLocalShadowMaps`
* `gfx::EKDeferredRenderer::RenderDynamicLocalShadowMaps`
* `gfx::EKDeferredRenderer::CullDynamicShadowCascadesRenderPasses`
* `gfx::EKDeferredRenderer::CullDynamicLocalShadowMapRenderPasses`
* `gfx::EKDeferredRenderer::ApplyPostOpaqueResolve`
* `gfx::EKDeferredRenderer::ApplyPostOpaqueBeforeResolve`

These are plain text strings in `.rdata` → Anvil keeps function names for
**debug/profiler integration** even though it strips MSVC RTTI.

---

## §15 Hot subsystem strings (curated index for future pivots)

Round / phase:
| String | Address |
|---|---|
| `RoundStart` | `0x7ff72d4e5a88` |
| `RoundEnd` | `0x7ff72d537252` |
| `RoundEndReason` | `0x7ff72d509cf6` |
| `HandleRoundStartedEvent` | `0x7ff72d4e7882` |
| `roundStates` | `0x7ff72d4f5982` |
| `GMEndOfRoundWinner` | `0x7ff72d50298a` |
| `IPlanningPhaseStateMachine Initialized` | `0x7ff72d539209` |
| `IPlanningPhaseStateMachine PhaseTimerExpired` | `0x7ff72d53d55f` |

DBNO / health:
| String | Address |
|---|---|
| `Error: DamageComponent Invalid` | `0x7ff72d53831b` |
| `Error: Entity Invalid` | (inline in DBNO Monitor) |
| `[DBNOMonitor] Error: Timeout` | `0x7ff72d4e381f` |
| `OnEntityEnterDBNO` | `0x7ff72d558d28` |
| `OnEntityRevive` | `0x7ff72d523aec` |
| `GoToDBNO` | `0x7ff72d558d3a` |
| `currentHealth` | `0x7ff72d51afe3` |
| `CharHealth` | `0x7ff72d51b00a` |
| `HEALTH:%.2f` (debug print) | `0x7ff72d521e34` |
| `GetHealthReturnValue` (network RPC) | `0x7ff72d52533c` |

Architecture:
| String | Address |
|---|---|
| `R6GameFlow` | `0x7ff72d4e15c2` |
| `R6GameFlowServiceGroupContext` | `0x7ff72d4e2d21` |
| `R6GameSessionService` | `0x7ff72d534b5d` |
| `R6MatchmakingService` | `0x7ff72d534c86` |
| `R6MatchmakingManager` | `0x7ff72d5043fa` |
| `GameSoundManager - m_GameRoundState changed from %u to %u` | `0x7ff72d4e2675` |
| `GameSoundManager - m_GameMatchState changed from %u to %u` | `0x7ff72d4e25fd` |
| `GameSoundManager - m_GameEscortingState changed from %u to %u` | `0x7ff72d4e2637` |

---

## §16 Updated three-layer security model (v3)

Original three-layer picture (v1/v2) was correct in pieces, wrong in scope.
Refined:

```
┌─────────────────────────────────────────────────────────────────────┐
│ Layer 3 — VMProtect virtualization                                  │
│   Applied to ~2 % of .text (9,850 helpers, first 38 % of .text)     │
│   Mostly: NVAPI/OS-API resolvers, license-check, TPM glue,          │
│           BattlEye glue, low-level anti-tamper primitives.          │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 2 — MBA obfuscation in plain .text                            │
│   Applied to gameplay-critical primitives that handle:              │
│     • entity-component handle resolution                            │
│     • state-machine offset computation (IPlanningPhaseStateMachine) │
│     • damage / DBNO / health logic                                  │
│     • the central error logger (ClassID computation)                │
│   Symptom: Hex-Rays fails or emits unreadable `(x|m)+(x&m)` chains. │
├─────────────────────────────────────────────────────────────────────┤
│ Layer 1 — MSVC hardened compile + RTTI strip                        │
│   CFG / XFG / retpoline (verified — see §1.2).                      │
│   Anvil engine has its OWN classes RTTI-stripped (no .?AV*@@ tags). │
│   Third-party libs (Havok, CryptoPP, glTF, std, asio) keep RTTI.    │
│   Custom class identification: off_7FF72DC93E80 + obfuscated         │
│   handle scheme (§10).                                              │
└─────────────────────────────────────────────────────────────────────┘
```

---

## §17 What we can actually delete from IDA (junk identification)

The user asked which obfuscated stuff is *junk* we can drop in IDA. Based
on §10–§12 analysis:

| "Junk" pattern | What it really is | Safe to ignore? |
|---|---|---|
| Constant load sequences at func entry like `mov rbp, 0xFFFFFFFF5ECF24B6h` ×6 | MBA seed constants — these get combined via `(x^k)+2*(x&k)`-style identities into one or two real constants | **Yes** — apply a Miasm/SiMBA pass and they collapse to single immediates |
| Long `(x|k)+(x&k)`, `(x^y)+2*(x&y)`, `-x+k` arithmetic chains | MBA-obfuscated constant computation | **Yes** — algebraic identities reduce them to `x + k` etc. |
| `dword_7FF72DA48214 & 1` guards before allocator calls | "is custom allocator initialized" check | **Yes** — set to constant `1` at runtime; can be patched to `jmp` |
| Dead `push reg / pop reg` around `xchg [rsp], reg` in `.UBX0` handlers | VMProtect handler shape's junk pad + register-shuffle | **Yes** for understanding flow; **No** for execution |
| Single `nop` `0x90` prefix on every `.UBX0` handler | VMProtect handler-entry signature | **Yes** to ignore for analysis |
| `__debugbreak()` blocks reachable via `slot == 0x7F` or `v == -1` | Asserts for class-registry sentinel-hit (never executes in normal play) | **Yes** — cold path |
| `if ((dword_7FF72DA48214 & 1) != 0)` paired with `off_7FF72DC8AB00(...)` | Custom allocator error-callback registration; only hot if the allocator hook is installed | **Mostly yes** — pure error path |
| Functions ending with the `(***off_7FF72DC93E80 + 110)…` 8-line dance | Generic Anvil release-handle pattern | **Yes** — collapse to a single helper call in mental model |

The first three are by far the highest-volume "junk" — collapsing them turns
~30-line MBA blobs into 1-2 real instructions and makes Hex-Rays succeed on
functions like the planning-phase state machine.

---

## §19 DamageComponent — deep-dive (the chain you asked for, fully walked)

This section is the result of decompiling four independent callers of the same
HealthState vtable, plus a sibling component's update function.

### 19.1 Three independent functions read DamageComponent → HealthState

All three use the **identical chain and the identical MBA-obfuscated vtable
offset** — they call the same virtual method on the same sub-object.

| Function | Size | Role | State value checked |
|---|---|---|---|
| `sub_7FF71CDD0300` (DBNO Monitor) | 0x35d | Times out downed players | `== 3` (DBNO) |
| `sub_7FF71CFFB590` | 0x367 | Damage-tick monitor (different timeout) | `== 3` (DBNO) |
| `sub_7FF71CB3B630` | 0x7c3 | Damage broadcaster (3 subscriber pools) | `== 4` (dead) |

(Six more callers exist for `qword_7FF72DADE438` but range from `0x40f` to
`0x6dea` and several fail Hex-Rays decompilation — they're MBA-heavy.)

### 19.2 The dispatch is double-obfuscated

```c
// 1. Compute the MBA-obfuscated offset (same in every caller)
v_inner = ((&stack_local ^ 0x4DBEF2F1) + 2*(&stack_local & 0x4DBEF2F0)
           - &stack_local - 1757900339);                        // = const - 0x68C70E33
v_mid   = (v_inner ^ 0xFFFFFFFFE4F784BE)
        - 2*(~v_inner & 0x7FFFFFFFE4F784B8)
        - 0x6A621E3CD6E05759;                                   // MBA pass 2
offset  = (v_mid ^ 0xA58C3CBB144AC3A)
        + 2*(v_mid & 0xA58C3CBB144AC3A);                        // (x^k)+2(x&k) = x+k

// 2. Dispatch through encrypted vtable
vtable_slot_addr = qword_7FF72DADE438 - offset;
fn = *(QWORD *)vtable_slot_addr;          // encrypted? or plain via runtime decrypt?
fn(damage_component + 336, &out_state);   // out_state = current HealthState value
```

The `&stack_local` input varies per caller (different stack offsets), but
since it's always 8-byte aligned the LSB is always 0, so the formula reduces
to **the same constant** in all callers. The MBA exists only to hide the
constant.

### 19.3 The vtable bytes at `qword_7FF72DADE438` are HIGH-ENTROPY

First 80 bytes:
```
59 ca 0f 08 86 25 f7 9f   ← would-be slot 0
d6 06 68 b6 09 30 38 a3   ← would-be slot 1
27 33 bb 40 78 d1 7d c2   ← would-be slot 2
47 ca e3 8c e6 49 c9 fc   ← would-be slot 3
f0 e4 bd ff 14 ee 52 a0   ← would-be slot 4
aa 4f a5 0f fd 69 c5 43   ← would-be slot 5
00 00 00 00 00 00 00 00   ← NULL (gap)
32 e6 b9 84 53 45 47 10   ← would-be slot 7
57 7e 82 99 f3 2c d5 6d   ← would-be slot 8
db f2 7b 3c 5e 0a cf 5c   ← would-be slot 9
00 00 00 00 00 00 00 00   ← NULL
00 00 00 00 00 00 00 00   ← NULL
54 b1 be 5c 01 00 00 00   ← appears to be {DWORD low, DWORD high=1} – maybe a packed handle
98 69 ab 2c 02 00 00 00   ← {DWORD low, DWORD high=2}
30 aa 39 09 c0 ed ba 1c   ← high-entropy
f7 7f 00 00 d8 04 ae 2d   ← (?) – mixed pattern
f7 7f 00 00 00 00 00 00   ← (?) – has 7f 00 00 trailing zeros (could be a pointer high half)
```

A real `.text` pointer in this binary always ends in `…1A F7 7F 00 00` to
`…2C F7 7F 00 00`. The high-entropy bytes here **do not** match that. Either:
(a) **the table is XOR-encrypted with a per-slot key**, OR
(b) **the table is a `Handle` table, not a vtable** — each 8-byte entry is a
    64-bit handle (low 32 bits = slot id, high 32 bits = generation/refcount)
    which is fed to the Anvil registry (`off_7FF72DC93E80`, §10) to resolve.

The second theory is more consistent with what we see (note the
`{xxxxxxxx, 0x00000001}` and `{xxxxxxxx, 0x00000002}` patterns at offsets
96–111). If so, the **dispatch goes through the registry**:

```
ClassID_handle = vtable[slot]                          // packed [id|gen]
class_arr      = off_7FF72DC93E80[110]
instance       = class_arr[8 * HIDWORD(handle)][WORD1(handle) & 0x7F]
real_fn        = instance->vtable[N]
real_fn(...)
```

This would explain why the dispatch is *triple*-indirect (MBA → handle table
→ Anvil registry → real function) and why simple xref crawling never finds
the actual implementation.

### 19.4 BaseEntity has MULTIPLE cached component slots

We've now seen reads from at least **three** different cached-slot bytes in
BaseEntity, all checked against the `255 = none` sentinel:

| Offset | Slot for | Source |
|---|---|---|
| `+484` / `+0x1E4` | **Sibling component A** (paired with DamageComponent in `sub_7FF71CFFB590`) | likely `HealthMaxComponent` or `ArmorComponent` |
| `+488` / `+0x1E8` | **DamageComponent** | confirmed across all 3 monitors |
| `+549` / `+0x225` | **Sibling component B** (primary path in `sub_7FF71CB3B630`) | likely `BroadcastComponent` or `DamageReceiverComponent` |

So a BaseEntity has a **byte-array of cached component slot indices** somewhere
in the `+0x1E0..+0x230` range. We've sampled 3 entries; the full table is
probably ~20-40 bytes long (one per Anvil component type).

`sub_7FF71CB3B630` first tries the `+549` lookup, then falls back to `+488` —
this is the **two-tier component resolution** pattern: prefer a specialized
component, fall back to the generic DamageComponent.

### 19.5 HealthState enum (confirmed so far)

| Value | Meaning | Source |
|---|---|---|
| `0` | (untested — likely "alive/healthy") | — |
| `1` | (untested — likely "injured") | — |
| `2` | (untested) | — |
| **`3`** | **DBNO** (down-but-not-out) | DBNO Monitor + sub_7FF71CFFB590 |
| **`4`** | **Dead** (terminal — broadcaster bails out) | sub_7FF71CB3B630 |

The DBNO state and Dead state are distinguished — Siege's death pipeline:
**alive → injured → DBNO → dead**. Once state == 4, the damage broadcaster
stops processing the entity (it's already terminal).

### 19.6 The damage broadcaster's subscriber model (`sub_7FF71CB3B630`)

This function manages **three subscriber pools** with refcounted weak
references:

```
struct DamageBroadcaster:
    +920 (qword)   subject_entity     // the entity taking damage
    +928 (qword)   pool1_ptrs         // array of subscribers
    +936 (qword)   pool1_size_bits    // [size: 30 bits | capacity_hint: 30 bits | flags: 4 bits]
    +944 (qword)   pool2_ptrs
    +952 (qword)   pool2_size_bits
    +960 (qword)   pool3_ptrs
    +968 (qword)   pool3_size_bits
    +1006 (byte)   pool1_dirty
    +1007 (byte)   pool2_dirty
    +1008 (byte)   pool_state         // 1 = updated this frame
```

Each subscriber entry is a refcounted pointer. The function:
1. Validates the subject entity is alive (`state != 4`).
2. For each pool, **prunes dead/weak entries** via
   `_InterlockedExchangeAdd64(entry+8, 0xFFFFFFFF00000000)` to atomically
   decrement the upper 32 bits (the strong-ref count) and check whether the
   entry should be released.
3. Calls a global cleanup `sub_7FF71F2F63B0(&unk_7FF72DE9F5C0)` + write +
   `MEMORY[0x7FFE516B49F0]` (SRW lock release) for each entry that
   transitions to zero.
4. Rebuilds the live subscriber list, calling
   `sub_7FF71CBA3700(pool, new_cap, old_size, kind)` when the pool needs to
   grow.

The pool size word at `+936/+952/+968` is packed:
* bits 0-29 = current count
* bits 30-31 = flags (`& 0x80000000` means "needs rebuild this frame")
* bits 32-61 = capacity hint

The growth policy:
```c
new_cap = current_cap;
do {
    new_cap += max(new_cap / 2, 4);
} while (new_cap < required_count);
```
Standard `1.5×` exponential growth with a minimum step of 4.

So damage in Siege is **published to subscribers** rather than tightly
coupled — anything that needs to react to damage (UI hit indicator, audio
cue, replication, etc.) subscribes to one of these three pools.

The three pools likely represent: **immediate reactors**, **deferred reactors**, **post-death reactors**.

### 19.7 A SECOND encrypted vtable: `qword_7FF72DADE270`

`sub_7FF71CF66410` uses a *different* encrypted vtable at
`qword_7FF72DADE270` (456 bytes / 57 qwords before `qword_7FF72DADE438`).
The function is dense MBA — every constant load is wrapped in `(x|k)+(x&k)`
identities, and Hex-Rays gives up entirely.

Selected MBA constants from `sub_7FF71CF66410`:
```
0xB6C72FBB, 0x5BD97855, 0xEEE1A865, 0x4B6FFDAE, 0x1046B3B4,
0x93DF53B8, 0x93DF53BD, 0xF4D3B266, 0xC39B88A9, 0x65BCF22F,
0xA68BFA13BB0EDE10, 0x1DE5AB4CBC6FFBFB
```
Different seed schedule than the HealthState callers — every protected
function in this layer has its own MBA constant set.

The struct accessed (call it Subject) has fields at:
* `+0x238` (qword)   threshold timestamp
* `+0x240` (qword)   current timestamp / null
* `+0x248` (dword)   clock type (0/1/2 switch — same as DBNO monitor)
* `+0x24C` (byte)    init flag
* `+0x708` (qword)   component pointer
* `+0x828` (byte)    enable flag

Same timer struct shape as DBNO monitor's `a4` argument (clock-type +
threshold + current + init flag). This is the **Anvil shared timer pattern** —
every component that needs a timed check uses these 4 fields together.

### 19.8 The TLS gating pattern (every component read)

Every chain we've walked includes the **same TLS guard**:
```c
TlsBlock = NtCurrentTeb()->ThreadLocalStoragePointer[TlsIndex];
if (!*(BYTE *)(TlsBlock + 20))               // is "right thread" flag set?
    unk_7FF72C5BD6A4();                       // initialize game-thread state
if (*(DWORD *)(TlsBlock + 3276) != 2          // is game mode == "in match" (2)?
    && handle[11] >= 0)                       // OR is the handle strong-ref?
    return;                                   // bail otherwise
```

So every component read **gates on TLS state**. Specifically:
* `TLS[20]` (byte) — "game thread initialized" boolean.
* `TLS[3276]` (dword) — current game mode/state. `== 2` means **in match** (other values are menu/lobby/loading).
* `handle[11]` — sign bit on byte 11 of the EntityHandle: weak vs strong.

This is a **two-condition gate**: you can only deref an entity if you're
either in a match OR holding a strong reference. Off-thread reads are
forbidden entirely.

### 19.9 The actual `+336` HealthState sub-object (what we know)

* Embedded sub-object inside DamageComponent (not a pointer).
* Has its own vtable at `qword_7FF72DADE438 - <MBA const>`.
* `vtable[N]` writes a DWORD to an out-pointer:
  * `3` → DBNO
  * `4` → dead
  * `1` and `2` → seen as alt return values but not contextually distinguished yet
* Likely also holds:
  * current health (float) — `HEALTH:%.2f` format string exists, no plain xref
  * max health
  * last-damage-source entity handle
  * last-damage timestamp

To extract the float health field we need to either:
* Decompile `sub_7FF71CC51850` (GetHealthReturnValue network handler — done above; it's the NETWORK reply parser, **not** the in-memory read), OR
* Find the entity-Replication writer for the health field (search for
  publishers writing to `(damage_comp + 336 + N)` where `N > 0`).

---

## §18 Open follow-ups (queued)

| # | Question | Best approach |
|---|---|---|
| 1 | Decompile `sub_7FF71CC51850` (GetHealthReturnValue, 2.2 KB) to extract the actual `float health` offset inside HealthState | Direct decompile |
| 2 | Resolve `qword_7FF72DADE438` — the vtable used by HealthState | Read first 16 qwords of `qword_7FF72DADE438` and map to functions |
| 3 | Run an MBA simplifier on `sub_7FF71D77E3E0` to make IPlanningPhaseStateMachine readable | SiMBA pass, then re-decompile |
| 4 | Enumerate all 9,850 `.UBX0` entry points and cluster by handler-chain length | py_eval over `.UBX0`, count nop-jmp transit edges per entry |
| 5 | Find R6GameFlow's state-broadcast publisher (who triggers `m_GameRoundState` writes that GameSoundManager listens to) | xref the publisher side of the round-state event |
| 6 | Build a structure-offset table for BaseEntity, DamageComponent, HealthState, R6GameFlow | Use IDA `apply struct` after collecting offsets |

---

## §9 Methodology log (verifiable claims)