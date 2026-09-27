> **SUPERSEDED 2026-09-18 — see `00_START/README.md`.**
> Kept for its detail and history. Where it disagrees with that file,
> that file is correct.

> # ⚠️ 2026-09-16 — READ `SESSION_HANDOFF_2.md` FIRST
>
> A later session solved the **skeleton topology** (20/20 bones with full
> parent chains, from the game's own SkeletonDescriptor) and corrected
> several claims in this file.
>
> **Superseded here:** the 99-vs-32 bone "remap" hunt in §31d/§32/§33 —
> those are *different bone sets*, no remap exists. Also: the count mask is
> **29-bit** (`0x1FFFFFFF`), the pose stride is **`0x20`** not `0x40`, and
> "41 bone writers" was a bad pattern (really 5, one live).
>
> **Still correct here:** the crypto templates, the TLS keys, and the crash
> rules in §8.

# SESSION HANDOFF — read this first

**Date:** 2026-09-15
**Purpose:** everything needed to resume without re-deriving anything.

---

## 0. THE 60-SECOND VERSION

- Target: **Rainbow Six Siege**, `RainbowSix.exe`, BattlEye NOT running.
- Built an **internal (in-process) RE tool** — `Bytecode-Internal` — that
  injects into the game and serves an HTTP API from inside it.
- **Solved the bone/skeleton problem** your research was stuck on since
  §16e: found the animated bone matrix writer, decoded its encryption,
  and read live bone transforms for 5 characters simultaneously.
- **Mapped the entire TLS block**: 10,673 slots, 5,985 identified as
  crypto keys, validated 9/9 against hand-decoded ground truth.
- **Crypto template T7 verified end-to-end** on live captured data.

---

## 1. WHERE EVERYTHING LIVES

```
C:\Users\hhhuh\Downloads\
├── Siege-Research\                       <- YOUR EXISTING RESEARCH
│   ├── INVENTORY.md                      index of ~10,600 lines of prior work
│   ├── SESSION_HANDOFF.md                <- THIS FILE
│   └── 01_active_decrypter\
│       ├── recon_notes\
│       │   ├── SIEGE_RECON_V5.md         <- ⭐ ALL NEW FINDINGS (this session)
│       │   ├── SIEGE_RECON_V4.md         prior session
│       │   └── (v1-v3 docs)
│       ├── Siege External\CRYPTO_MAP.md  your T1-T6 catalogue (now partly stale)
│       ├── r6_decrypt_external.py        external decrypter (written, runs)
│       └── tls_mapper.py                 external TLS mapper (superseded)
│
├── Bytecode-Internal\                    <- ⭐ THE NEW TOOL
│   ├── CMakeLists.txt
│   ├── stamp.cmake                       timestamped DLL copies
│   ├── injector\main.cpp
│   └── src\
│       ├── dllmain.cpp                   lifecycle + ordered teardown
│       ├── core\mem.h                    SEH-guarded in-process memory
│       ├── core\scan.h                   pattern/value scanning
│       ├── core\hwbp.h/.cpp              hardware breakpoints (VEH + DR0-3)
│       ├── crypto\tls.h                  TLS directory + block access
│       ├── crypto\tls_map.h/.cpp         exhaustive slot classifier
│       ├── crypto\decrypt.h/.cpp         T7/T7b/T8 + T2 trampoline
│       ├── ipc\server.cpp                HTTP routes
│       ├── ipc\http.h, json.h            (copied from external Bytecode)
│       └── ui\web.h                       embedded browser UI
│
└── Reverse Engineering\Unpackers\Bytecode\   the ORIGINAL external tool
```

---

## 2. HOW TO RESUME (exact commands)

```bat
:: build
cd C:\Users\hhhuh\Downloads\Bytecode-Internal
cmake -B build -A x64
cmake --build build --config Release

:: inject (game must be running)
cd build\Release
Inject.exe

:: use
curl -X POST http://127.0.0.1:9998/status  -d "{}"
curl -X POST http://127.0.0.1:9998/tls_map -d "{\"limit\":0}"

:: unload cleanly (frees the DLL so the next build can link)
curl -X POST http://127.0.0.1:9998/unload -d "{}"
```

**Port 9998** — 9999 belongs to the original external Bytecode, and both
can run at once.

**Iteration loop that works:** unload → rebuild → re-inject, all without
restarting the game. Used five times in a row this session.

---

## 3. VERIFIED CONSTANTS (this build)

| Thing | Value |
|---|---|
| Module base (live AND IDB) | `0x7FF792F90000` — **ASLR delta is ZERO** |
| Module size | 457,900,032 |
| `.text` | `0x7FF792F91000`, 301,651,190 bytes |
| `.data` | `0x7FF7A5B6D000` |
| **TlsIndex** | **`0`** (at `0x7FF7A5D1030C`, RVA `0x12D8030C`) |
| **TLS raw data** | **`0x7FF7A7585CF8` … `0x7FF7A75A2608`** |
| TLS raw size | `0x1C910` (117,520 bytes) |
| IDB path | `…\PeDumper\build\x64\Release\dumps\RainbowSix.exe\RainbowSix.exe_dump.exe.i64` |

> IDA addresses are usable **directly** in the live process. No rebasing.

---

## 4. THE BONE / SKELETON SOLUTION ⭐

This is the thing §16e of your V4 notes called "Not yet cracked."

### Addresses

| What | Address |
|---|---|
| Bone Vec4 write (sig hit) | `0x7FF79727B859` |
| T7 decrypt (`rol`+`sub`) | `0x7FF79727B7D2` |
| **Post-decrypt (plaintext in r10)** | **`0x7FF79727B7D9`** |
| enc_base store | `0x7FF79727BFF1` |
| Containing function | `sub_7FF79727A530` (0x3389 bytes) |

### Signatures (verified unique)

```
bone Vec4 write   ?? 89 ?? ?? 38 ?? C7 ?? ?? 3C 00 00 80 3F
T7 base decrypt   49 C1 C2 04 49 29 D2
```

### The chain

```
rsi                    = skeleton object ("this")
enc  = [rsi+0x158] + TLS[0x9850]
base = ROL64(enc, 4)  - TLS[0x9800]
bone[i] = base + i*0x40
pos[i]  = *(Vec4*)(bone[i] + 0x30)      // (x, y, z, 1.0)
count   = TLS[0x18]
```

A second parallel buffer at `[rsi+0x160]`, stride `0x38` — likely
per-bone metadata (parent index / flags).

### Per-bone layout (64 bytes, row-major 4x4)

| Offset | Content | w |
|---|---|---|
| `+0x00` | rotation row 0 | 0.0 |
| `+0x10` | rotation row 1 | 0.0 |
| `+0x20` | rotation row 2 | 0.0 |
| `+0x30` | **translation** | **1.0** |

### Proven live

Real matrix read from a live character:
```
row0: -0.8575  -0.1099  -0.9678   w=0.0
row1:  0.5743   0.7155  -0.3977   w=0.0
row2:  0.7473  -0.6566  -0.1022   w=0.0
pos : -86.002 -82.218   36.379    w=1.0
```

Five distinct skeletons captured simultaneously, each with its own buffer
and distinct world position:

| rsi (skeleton) | r10 (bone buffer) | bone[0] position |
|---|---|---|
| `0x176E0250670` | `0x176D3F0B830` | (-97.61, -16.19, 54.68) |
| `0x176BE428700` | `0x176D5ECC0F0` | (-38.43, 22.48, -3.78) |
| `0x176D08262B0` | `0x176D6E23F90` | (-85.68, 83.82, 70.27) |
| `0x176E0366060` | `0x176DA1881D0` | — |
| `0x176E02EF3E0` | `0x176D6F5AAC0` | — |

> Entity 3 iterates `r13` over `0x07–0x0C` while the others run
> `0x1B–0x1F`. Different bone-index range — possibly the local player.
> **Unresolved.** User reported 6 entities; only 5 were captured.

### Two ways to get the buffer

1. **Breakpoint `0x7FF79727B7D9`, read `r10`** — the game decrypts for
   you, no crypto needed. (This is what produced the data above.)
2. **Compute it** — `ROL64([rsi+0x158] + TLS[0x9850], 4) - TLS[0x9800]`.
   Works with no breakpoint.

---

## 5. CRYPTO TEMPLATES (this build)

⚠️ **Your V4 T1 constants are DEAD.** `0x801DE0677929AF10` and
`0x758BFE7BAD72DEF7` have **zero** hits. Every hard-coded constant in
`CRYPTO_MAP.md` / `decrypt_t*.h` must be re-derived.

| # | Formula | External? | Status |
|---|---|---|---|
| **T7** | `ROL64(enc,4) - TLS[k]` | ✅ YES | **VERIFIED end-to-end** |
| T7b | `enc - TLS[k]` | ✅ YES | decoded |
| T8 | `ROR64(enc, TLS[k]&63)` | ✅ YES | decoded |
| T9 | not/xor/and MBA + TLS | ✅ YES | decoded |
| **T2** | `table[f(RSP)]` | ❌ **NO** | needs in-process trampoline |

**T2 is the only one external tooling can never do** — its key index is
computed from the live RSP at the call site.

> ⚠️ **CORRECTED 2026-09-15 — see `SIEGE_RECON_V5.md §20`.**
>
> Two claims that used to sit here were **wrong** and are retracted:
>
> - ~~"~600 T2 sites"~~ — produced by a broken classifier that matched
>   the **TLS prologue** (`mov ecx,[rip+_tls_index]` … `mov rax,gs:[0x58]`
>   … `mov rdx,[rax+rcx*8]`). It called 32 of 60 ordinary array-walk
>   sites T2.
> - ~~"key table at `0x7FF7A6C68440`"~~ — that address is sparse mixed
>   `.data` (two wide values, then ~96 zero bytes) and the "pointer" in
>   it is unaligned and unmapped. The classifier's `table` field was
>   resolving to `0x7FF7A5D1030C`, which is **`_tls_index`**, not a key
>   table. No T2 key table has been located yet.
>
> **Now fixed** — the detector requires RSP to enter the index dataflow
> and rejects any REX.W form of `mov r64, gs:[0x58]`. Current honest
> count: **177 T2 sites per 400 RSP candidates**; ground truth still
> 3/3; a 10-site audit found 0 leaked TLS prologues.
>
> First hand-confirmed T2 site: **`0x7FF7930BB88D`** (see §20d) — uses
> `xor`/`and` against `0x7178E006` then `lea rcx,[rcx+r10*2]`, the MBA
> identity `x+y == (x^y) + 2*(x&y)`.

### T7 end-to-end proof

```
captured r10 (enc) = 0xFA0E95D4BDEC0FAF
captured rdx (key) = 0xA0E95BCA8E6D268F   (== TLS[0x9800])
ROL64(enc,4) - key = 0x1815053D470
```
Canonical, 8-byte aligned, in the same heap band as the skeleton object.
Random bits do not land that way.

---

## 6. THE TLS MAP ⭐

```
10,673 slots · 279,848 sites · 301 MB scanned · 51 s · COMPLETE
```

| Role | Slots | Crypto? |
|---|---|---|
| `rot-count` | 1716 | ✅ |
| `sub-key` | 1554 | ✅ |
| `add-key` | 1515 | ✅ |
| `xor-key` | 796 | ✅ |
| `xor-key-bytewise` | 336 | ✅ |
| `mba-chain` | 68 | ✅ |
| `state-cmp` | 1029 | ❌ |
| `pointer` | 600 | ❌ |
| `guard-latch` | 233 | ❌ |
| `predicate` | 85 | ❌ |
| `counter` | 11 | ❌ |
| `UNKNOWN` | 2730 | — |

**5,985 keys · 1,958 ruled out · 2,730 unresolved.**

### Method (the only valid one)

Classify by **the opcode that consumes the value**. Never by value shape.
Proof that shape fails: three wide values adjacent to a known key —
`0x9728` is a key, `0x9738` is a branch predicate, `0x98C8` is a base
offset. A shape heuristic gets 2 of 3 wrong.

### Hand-verified slots (ground truth)

| Slot | Role | Value | Proven at |
|---|---|---|---|
| `0x18` | bone count (u32) | — | `0x7FF79727BA6A` |
| `0x1C` | init flag | `0x0` | `0x7FF79335916E` |
| `0x368` | rot count **(multi-use!)** | `0x23` | `0x7FF79335235C` |
| `0xD70` | sub key | `0x264371DF29D0D7FF` | `0x7FF79387FBFD` |
| `0x3BD8` | guard latch | `0x0` | `0x7FF793FB7196` |
| `0x5EC0` | MBA key | `0x16` | `0x7FF79550533F` |
| `0x8208` | rot count | `0x10` | `0x7FF796579C2A` |
| `0x9728` | byte-wise XOR key | `0x501FF8E9D66560C1` | `0x7FF79727C007` |
| `0x9738` | **predicate, NOT a key** | `0xC8BA7D90DAFC1409` | `0x7FF79727BB39` |
| **`0x9800`** | **T7 sub key** | **`0xA0E95BCA8E6D268F`** | `0x7FF79727B7D2` |
| **`0x9850`** | **T7 pre-add key** | **`0x4AC3DAA0B834A07B`** | `0x7FF79727BFDE` |
| `0x98C8` | **base offset, NOT a key** | `0xDF278E286694709F` | `0x7FF79727BFB9` |
| `0xE4A8` | sub key (2nd subsystem) | — | `0x7FF799974C64` |

### Template vs live keys — RESOLVED

Only **51 of ~14,500** slots differ, all runtime pointers in the low
region. `TLS[0x9800]` is byte-identical between the PE template
(`0x7FF7A7585CF8`) and a live per-thread block (`0x18119853D00`).

✅ **The crypto key block is NOT per-thread** — template reads are valid,
so external T7/T8 decryption is sound.

### ⚠️ Known limitation: multi-use slots

`TLS[0x368]` is hand-proven as a rotate key at one site, but the majority
verdict across its **337 sites** is `pointer`. The slot serves two
purposes. **A single role per slot is a simplification.** High-site-count
slots are the most likely to hide a minority crypto use — check the
specific site for anything load-bearing.

---

## 7. THE TOOL — what works, what doesn't

### Endpoints

| Route | Does |
|---|---|
| `/ping`, `/status` | health + module/TLS info |
| `/read`, `/read_typed` | memory reads (SEH-guarded) |
| `/scan_aob` | pattern scan |
| `/tls_read` | one slot, `live` or `template` |
| `/tls_verify` | template vs live diff |
| **`/tls_map`** | **exhaustive slot classification** |
| `/identify` | crypto template at a site |
| `/decrypt` | T7/T7b/T8 |
| **`/bp_capture`** | **hardware breakpoint + full registers** |
| `/unload` | clean teardown |

### Verified working
- In-process SEH-guarded memory — never faulted on a bad address
- Hardware breakpoints with full register capture
- TLS mapping at scale
- Clean unload → rebuild → re-inject **without restarting the game**
- Refuses cleanly when its port is taken

### NOT verified
- `/decrypt` T9 path returns "needs the site's MBA chain" — unimplemented.

### ⭐ `call_site()` — NOW EXECUTED AND VERIFIED (2026-09-15)

It was never run before because **it had no HTTP route**. Added
`/call_site`, gated behind `confirm:true`.

**First execution, verified exact.** Site `0x7FF7930BB89A`, 18 bytes of
pure register arithmetic (the T2 stack-hash):

```
xor rcx, 0x7178E006 ; and r10d, 0x7178E006 ; lea rcx,[rcx+r10*2]

in : rcx=0x1122334455667788  r10=0xAABBCCDD
out: 0x1122334464901796   == independent calculation, all 64 bits
```

**The T2 capability is proven** — the game's own crypto can be made to
run for us. See `SIEGE_RECON_V5.md §21`.

> ### ⚠️ IT ALSO CAUSED HOST CRASH #4 — read §21d
>
> Running the **full 31-byte** site with `rdi=r14=r15=0` killed the
> process: it contains `mov r9,[rdi+r14*8]` and `mov [r15], r9`, a read
> and a **write** through null.
>
> I expected `__try/__except` to catch it. **It did not.** Event log:
> `0xC0000005`, *"Faulting module: unknown"*, fault offset at a heap
> address — the fault was inside our own hand-emitted stub, which has no
> unwind information for SEH to use.
>
> **The SEH guard is a backstop for surprises, not a licence to execute
> code that dereferences invented registers.**
>
> Fixed: memory-touching snippets need a separate `allow_memory:true`
> opt-in (`lea` is exempt — it computes without dereferencing). The exact
> fatal call is now refused at `+6`.

Also replaced the snippet-safety check: it was a **flat byte scan** that
read the immediate bytes `78 71` of `xor rcx,0x7178E006` as a `js`, and
the ModRM `C2` of `mov r10,imm64` as a `ret` — it would have refused the
first real T2 site while reporting a branch that was not there. Now a
real x86-64 length decoder, which additionally refuses RIP-relative
operands (their displacement breaks when relocated into the stub).

`/call_site` args: `site`, `len`, `out_reg` (0-15), `confirm:true`,
optional `allow_memory:true`, plus any of `rax`…`r15`.

### Verified THIS session (2026-09-15)
- `/identify` agrees with hand-decoded ground truth on T7, T8, T7b (3/3).
- `/identify` T2 detection was **broken and is now fixed** — see §20 of
  `SIEGE_RECON_V5.md` and the corrected §5 above.
- `/identify` honestly reports `unknown` rather than guessing: it misses
  the bytewise-XOR site `0x7FF79727C007` and the pre-add site
  `0x7FF79727BFDE` instead of mislabelling them.
- `/scan_aob` hits verified by reading the bytes back — no phantom hits.
  ⚠️ **`limit:0` means "return nothing" here**, not "unlimited" (it does
  mean unlimited in `/tls_map`). Pass an explicit large limit.
- `/read` takes `address`, not `addr`.

---

## 8. CRASH HISTORY — read before using breakpoints

Three host crashes, all caused by tool bugs. **All fixed.** Two of my
diagnoses were wrong before the third was right; the wrong ones are
marked retracted in `SIEGE_RECON_V5.md`.

### The real cause

`clear()` could not disarm every thread (snapshot race, current thread
skipped, threads already mid-trap). A stale debug register then trapped,
the VEH saw `armed == false`, returned `EXCEPTION_CONTINUE_SEARCH` — and
since nothing else handles `EXCEPTION_SINGLE_STEP`, that became an
unhandled exception and killed the process.

**Signature:** capture succeeds and returns data, game dies moments
later, no fault at the breakpoint address.

### Fixes

1. **VEH self-disarms stale slots** in the trapping thread's own context
   and returns `CONTINUE_EXECUTION` — never `CONTINUE_SEARCH` for our own
   DR traps.
2. **No thread suspension.** `suspend` defaults to false everywhere,
   including teardown. Suspending game threads to install DRs risks
   freezing one that holds a lock the renderer needs.
3. **`clear()` order inverted** — remove DRs first, then flip `armed`.
4. **`install()` registers the handler before advertising itself.**
5. **`uninstall()` waits** 120 ms before removing the VEH, 80 ms after.

### Rules

- **Never** return `CONTINUE_SEARCH` from a VEH for a trap your own debug
  registers caused.
- **Never** suspend game threads to install debug registers.
- A missed breakpoint is always better than a dead host.

### Crash #4 (2026-09-15) — `call_site()`, see §21d

- **Never execute a copied snippet that dereferences memory unless every
  pointer operand is a verified-readable address.** SEH will *not* save
  you — it already failed to, once, because a hand-emitted stub has no
  unwind information.
- **Never hand-roll "safety" as a flat byte scan.** Decode instruction
  lengths properly, or refuse.
- A refusal must name *which* instruction and *why*. A bare `false` sent
  this session hunting a branch that did not exist.

---

## 9. NEXT STEPS (recommended order)

1. ~~**Test the T2 trampoline**~~ — ✅ **DONE 2026-09-15.** Executed and
   verified bit-exact; see §21. Along the way the T2 *detector* turned
   out to be broken (§20) and the snippet-safety check turned out to be a
   flat byte scan that lied (§21c). Both fixed.

   **What is left on T2:** the proof used a memory-free arithmetic
   snippet. Harvesting a real key still requires running a snippet that
   *does* touch the table — which needs `allow_memory:true` **and** real,
   verified-readable values in every pointer register. Get those from a
   `/bp_capture` at the site rather than inventing them. That is the
   remaining step, and it is the one that killed the host when done
   carelessly.
2. **Resolve the 2,730 UNKNOWN slots** — widen the 56-byte consumer
   window, add patterns for missed forms.
3. **Multi-role slot tracking** — record all roles per slot instead of a
   majority verdict, so cases like `TLS[0x368]` stop being hidden.
4. **View matrix / camera** — not yet found. The V4 camera AOB
   (`A4 70 7D BF …`) returns 0 hits in this build. Needed to project bone
   positions to screen.
5. **Find the 6th entity** and determine whether entity 3's odd `r13`
   range (`0x07–0x0C`) marks the local player.

---

## 10. DEAD V4 SIGNATURES — do not reuse

| Signature | Status |
|---|---|
| T1 const `0x801DE0677929AF10` | ❌ 0 hits |
| T1 const `0x758BFE7BAD72DEF7` | ❌ 0 hits |
| GameManager AOB `48 83 EC 38 4C 8B 0D …` | ❌ 0 hits |
| Camera AOB `A4 70 7D BF …` | ❌ 0 hits |
| TLS offsets `0x3C80`, `0x3A50`, `0x9C40`, `0x9E28` | ❌ gone |
| TLS `0x6FB8` | ⚠️ 1 site only |

The entity-list pipeline (GameManager → ELC → ENT2) needs re-deriving for
this build.

---

## 11. ENVIRONMENT NOTES

- **IDA MCP**: port **13337** (was misconfigured as 13338 — fixed in
  `.claude.json`). Auto-analysis of the 437 MB binary never completed in
  this session; `find_bytes` works, `decompile`/`disasm` mostly fail.
  Raw-byte reads via Bytecode + hand-decoding were used throughout.
- **External Bytecode**: `127.0.0.1:9999`. Its `/watch_bp_hits` is
  **broken** — returns 0 hits even on provably-hot code. Do not trust a
  0 result from it.
- **Internal tool**: `127.0.0.1:9998`.
