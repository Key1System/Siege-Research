# R6 Siege Crypto Map

> Comprehensive scoping doc for R6's obfuscation family, based on live IDA
> reverse of `RainbowSix_dump.exe.i64` (IDB base `0x7FF6FBEB0000`) and
> live user-provided reference disassembly from a newer build.
>
> Purpose: establish a real, honest picture of what R6's crypto actually
> is so we can build a **focused decrypter** rather than chase every one
> of the 700+ MBA sites. Educational / defensive RE only.

---

## §1 Reality check (updated 2026-07-17 — internal-DLL scope)

R6 doesn't use one crypto scheme — it uses a **family of templates**, each
with different math and different runtime dependencies. Any tool that
wants to decrypt "R6 encrypted pointers" needs to identify which template
a given site uses, then apply the matching inverse.

**Deployment model:** the decrypter ships as an **internal DLL** injected
into `RainbowSix.exe`. This changes what's decryptable:

- **TLS access is direct** — a normal `gs:[0x58]` load resolves the TEB,
  no `NtQueryInformationThread` dance.
- **T2 (stack-hashed MBA)** becomes decryptable via **trampolines** — for
  each site we care about we install a small stub that jumps into the
  game's own decrypt code and returns the plaintext. Zero re-implementation.
- **Symbolic-executor requirement goes away** — the game IS the executor.

Templates that used to be marked "external: NO" are marked "internal:
YES via trampoline" below.

---

## §2 Templates catalogued (internal-DLL scope)

Legend for the columns:
- **Formula** — the mathematical inverse, with `enc` = encrypted qword,
  `K*` = 64-bit compile-time constants, `TLS[N]` = live per-thread key.
- **How** — how the internal DLL handles it:
  - `formula` — replay the math directly in C++
  - `trampoline` — jmp into the game's own crypto site, harvest result
- **Sites** — how many sites of this template we've observed in the IDB.

| # | Name | Formula | How | Sites |
|---|---|---|---|---|
| T1 | TLS-rotated MBA (pure) | `plain = ROR((enc ^ K1) + K2, TLS[off])` | formula | 2 |
| T2 | Stack-hashed MBA | `plain = ROR((enc ^ f(rsp)) + g(rsp), TLS[off])` | trampoline | ~600 |
| T3 | Pure 3-key XOR-ADD-XOR | `plain = ((enc ^ K1) + K2) ^ K3` | formula | TBD (grep) |
| T4 | TLS-subtracted XOR | `plain = (global_enc - TLS[off]) ^ K1` | formula | TBD (grep) |
| T5 | HealthState decrypt | `raw = ROR(bswap_xor(enc, TLS[0x3C80]) - 0x4AB53B9A, TLS[0x3A50])` | formula | 1 (proven) |
| T6 | Anvil handle resolve | Table walk keyed by class ID | formula | 1 |

---

## §3 Template details

### §3.1 T1 — TLS-rotated MBA (PURE constants)

**Formula:**
```
plain = ROR( (enc ^ K1) + K2, TLS[SITE_TLS_OFF] )
```

**Fixed constants** (identical at BOTH observed sites in this build):
- `K1 = 0x801DE0677929AF10`
- `K2 = 0x758BFE7BAD72DEF7`

**Per-site variation:** only the TLS offset used for the rotate.

**Observed sites:**

| Site | Fn | TLS off | Notes |
|---|---|---|---|
| `0x7FF6FF6F6C52` | `hknp_PhysicsStep_A` @ `0x7FF6FF6F6C10` | `0x6FB8` | Physics-step world ptr |
| `0x7FF700F21CA0` | `sub_7FF700F21C90` | `0x9C40` | Unknown callback |

**Decompile (physics-step site):**
```c
world = __ROR8__(
    (*(_QWORD*)(a1 + 56) ^ 0x801DE0677929AF10) + 0x758BFE7BAD72DEF7,
    *(_QWORD*)(NtCurrentTeb()->ThreadLocalStoragePointer[TlsIndex] + 0x6FB8)
);
```

**Inverse (C++, external):**
```cpp
uint64_t decrypt_t1(uint64_t enc, uint8_t tls_rot) {
    uint64_t x = (enc ^ 0x801DE0677929AF10ULL) + 0x758BFE7BAD72DEF7ULL;
    return _rotr64(x, tls_rot & 63);
}
// tls_rot fetched once via RPM: TLS[SITE_TLS_OFF] & 63
```

### §3.2 T2 — Stack-hashed MBA (external-undecryptable)

**Same overall shape as T1** but K1/K2 are NOT compile-time constants —
they're computed from a hash of the runtime `rsp+offset` (typically some
early stack local like a temporary buffer). Because RSP is unpredictable
outside the process, we can't reproduce K1/K2.

**Example disasm (`sub_7FF7010A7E10`):**
```asm
v3 = (unsigned __int64)&v72 ^ 0x468C16F9;             ; &v72 = stack local
v4 = -1628873284LL - (uint64_t)&v72;
v5 = ((((&v72 & 0x468C16F8) ^ 0xFFFFFFFFA75C09E0) + ...)  // full MBA polynomial
v7 = *(_QWORD*)(a1 + 112) ^ *(_QWORD*)(~(...) + qword_7FF70C5A0E98)
     + *(_QWORD*)(qword_7FF70C5A0EE8 + 2*(v5 & MASK) - (v5 + MASK));
v8 = __ROR8__(v7, TLS[0x9E28]);
```

**Why external tools can't decrypt this:**
- The two `qword_7FF70C5A0E?8` tables hold ~4 KB of 8-byte entries. The
  MBA polynomial computes an index (0..N-1) into these tables from
  `&v72` (a specific stack address).
- Different callers of the same site produce different `&v72` → different
  index → different decrypt.
- To reproduce externally, you'd need to symbolically execute the entire
  caller function up to the crypto site.

**Site count:** ~600 (rough estimate — every function using encrypted
per-instance salt uses this template).

**Practical takeaway:** we can't build a general T2 decrypter. Any tool
that needs T2 values has to either (a) hook the game internally or
(b) run a symbolic executor per-site. Both out of scope for read-only
external.

### §3.3 T3 — Pure 3-key XOR-ADD-XOR

**Formula:**
```
plain = ((enc ^ K1) + K2) ^ K3
```

**Reference disasm (user-provided, different build):**
```asm
mov r9,  <K1>                 ; movabs r9, imm64
xor r9,  [r12+18]             ; r12 = struct base; +18 = encrypted field
mov rax, <K2>
add rax, r9                   ; rax = (enc ^ K1) + K2
mov r15, <K3>
xor r15, rax                  ; r15 = plaintext ; ZF -> null-check
```

**External inverse:** trivial — no runtime dependency.
```cpp
uint64_t decrypt_t3(uint64_t enc, uint64_t K1, uint64_t K2, uint64_t K3) {
    return ((enc ^ K1) + K2) ^ K3;
}
```

**Where this template is used:** engine-singleton pointer decrypts (like
the `World*` pointer). Fewer variants; each site has its own K1/K2/K3
triple but the shape is stable.

**Extraction:** IDA sig-scan finds the exact byte sequence, disassembly
gives us K1/K2/K3 for each site. Manageable.

### §3.4 T4 — TLS-subtracted XOR (single-key form)

**Formula:**
```
plain = ((*global_ciphertext) - TLS[SITE_TLS_OFF]) ^ K1
```

**Reference disasm (user-provided, different build):**
```asm
mov ecx, [TlsIndex]
mov r9,  gs:[0x58]                 ; TEB->ThreadLocalStoragePointer
mov r9,  [r9+rcx*8]                ; TLS[TlsIndex]
mov r9,  [r9+0x9370]               ; runtime key = TLS[0x9370]
movzx ecx,[r12+0x71D1]             ; plain flag byte
mov rax, [Test.exe+0x110AC5E8]     ; encrypted qword in .data
sub rax, r9                        ; enc - TLS_key
mov r9,  <K1>                      ; constant xor mask
xor r9,  rax                       ; plaintext
```

**External inverse:** read global once, read TLS once, XOR.
```cpp
uint64_t decrypt_t4(uint64_t enc_global, uint64_t tls_val, uint64_t K1) {
    return (enc_global - tls_val) ^ K1;
}
```

**Note on the user's TLS insight:** the `gs:[0x58]` + `[TLS+off]` sequence
looks intimidating but **externally it's just two RPM reads** — read TLS
base (via `NtQueryInformationThread` → TEB → ThreadLocalStoragePointer),
then read the specific TLS offset. Once you have the value, it's a static
constant for that thread. Not a real security feature against external
readers.

**Where used:** static (`.data`-resident) globally-encrypted pointers. R6
uses this for engine singletons that need to survive across threads.

### §3.5 T5 — HealthState decrypt (recon MD §9)

**Verified formula** — proven working against live game via the
`/r6_decrypt_health` endpoint we shipped:

```cpp
uint32_t decrypt_health(uint8_t enc[4], uint64_t tls_key /*TLS[0x3C80]*/,
                        uint32_t tls_rot /*TLS[0x3A50]*/) {
    uint32_t raw = 0;
    for (int i = 0; i < 4; ++i) {
        raw |= (uint32_t)(enc[i] ^ ((tls_key >> (i*8)) & 0xFF)) << (i*8);
    }
    raw = (raw - 0x4AB53B9AU) & 0xFFFFFFFFU;
    uint32_t r = tls_rot & 0x1F;
    if (r != 0)
        raw = (raw >> r) | (raw << (32 - r));
    return raw;   // 3=DBNO, 4=dead, 0-2=alive
}
```

### §3.6 T6 — Anvil handle resolve

Not really "crypto" — it's an indexed lookup through the
AnvilClassRegistry, but recon MD §10 documented the recipe. Handle format
is `{gen:32 | flags:2 | slot:30}`. Resolve:
```
class_arr  = *(QWORD*)(g_AnvilClassRegistry + 0x370);
class_info = class_arr[HIDWORD(handle)];
slot_byte  = *(BYTE*)(class_info + WORD1(LOW(handle)));
instance   = *(QWORD*)(g_AnvilClassRegistry + 0x378)[slot_byte & 0x7F];
```

Recon MD §16b noted that in the current build `+0x370` reads as zero —
the offsets may have shifted. Needs re-verification before using.

---

## §4 Global lookup tables

Several T2 sites reference these — worth documenting even though we can't
use them for a general decrypter:

| Symbol | IDB address | Purpose |
|---|---|---|
| `qword_7FF70C5A0E98` | (data) | MBA lookup table A — 4 KB of 8-byte entries |
| `qword_7FF70C5A0EE8` | (data) | MBA lookup table B — 4 KB of 8-byte entries |
| `qword_7FF70C568AB0` | (data) | Another MBA table, seen in HealthState-adjacent decrypt |
| `qword_7FF70C58B198` | (data) | Another MBA table |
| `TlsIndex` | `0x7FF70C6253BC` | dword — process's TLS slot (usually 0 for R6.exe) |

Contents are large blob of 64-bit values used as translation tables.

---

## §5 What's decryptable externally

For a read-only tool like Siege External:

| Template | Support? | Effort |
|---|---|---|
| T1 | ✅ Full | ~30 lines — 2 sites hardcoded |
| T2 | ❌ Skip | Would need symbolic executor |
| T3 | ✅ Full | Extract K1/K2/K3 per site via IDA sig scan |
| T4 | ✅ Full | Extract K1 + TLS offset per site; read TLS + global once |
| T5 | ✅ Full | Already implemented in Bytecode `/r6_decrypt_health` |
| T6 | ⚠️ Partial | Handle format is known; live offsets need re-verification |

---

## §6 Design of the decrypter library

Location: `Siege External\src\crypto\`

Files:
- `crypto/types.h` — `enum TemplateId`, `struct Site`, `struct Constants`
- `crypto/tls.h` — TLS-key snapshot from live process (once per attach, refresh on demand)
- `crypto/site_registry.h` — hard-coded table of every known site with its template + constants
- `crypto/decrypt_t1.h` — T1 inverse
- `crypto/decrypt_t3.h` — T3 inverse
- `crypto/decrypt_t4.h` — T4 inverse
- `crypto/decrypt_t5.h` — T5 (HealthState) inverse
- `crypto/decrypter.h` — unified public API: `decrypt(site_id, encrypted, out_plain)`
- `crypto/test.cpp` — table of known ciphertext → plaintext pairs, validates every template

Public API surface:
```cpp
namespace crypto {

enum class SiteId {
    // T1 sites
    PhysicsStepWorld,     // 0x7FF6FF6F6C52
    UnknownCallbackT1,    // 0x7FF700F21CA0

    // T3 sites (populated as we discover them)
    // e.g. WorldPointer,  ...

    // T4 sites
    // e.g. UnknownGlobalT4A, ...

    // T5
    HealthState,
};

struct Result {
    uint64_t plain;
    bool     ok;
};

// One-shot: decrypt a specific known site.
Result decrypt(SiteId site, uint64_t encrypted);

// Batch: decrypt N same-site values (perf path).
void   decrypt_batch(SiteId site, const uint64_t* enc, uint64_t* out, size_t n);

// Read fresh TLS keys from the attached process (updates internal cache).
bool   refresh_tls(HANDLE proc, DWORD game_tid);

} // namespace crypto
```

---

## §7 Building the site registry

To turn "site X uses template T with constants C" from art into a
maintainable table, we need an IDA-side extractor that:

1. Finds all instances of each template's byte signature
2. For each hit, disassembles the surrounding N instructions
3. Extracts the constants (movabs imm64) and any TLS offset (`[rcx+IMM32]`)
4. Emits a C++ header (`site_registry.gen.h`) that the runtime consumes

For now, we hand-populate T1 (2 sites) and leave T3/T4 tables empty
skeleton for future adds.

---

## §8 What we're NOT building

- **Symbolic executor** for T2. That's a project unto itself.
- **VMProtect stub unwrapper** (`.UBX0`/`.UBX1`). Those are the vmp
  handler tables — outside crypto scope.
- **Generic MBA solver.** All the templates here have known-form inverses;
  we don't need to reverse arbitrary polynomials.

---

## §9 One-sentence summary

Four externally-decryptable templates (T1, T3, T4, T5) cover the practical
work; T2 is external-undecryptable by design and needs symbolic
execution; T6 (Anvil handle resolve) is a table walk, not crypto — a
focused ~600-line library with tested inverses handles everything a
read-only ESP tool actually needs.
