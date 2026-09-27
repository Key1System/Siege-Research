# Review — two UnknownCheats sources

**Date:** 2026-09-16
**Reviewed:**
- `r6 unlockall_[unknowncheats.me]_` (internal, D3D12 + ImGui + MinHook)
- `working chams 31.7.2026_[unknowncheats.me]_` (internal, D3D12 only)

**Status of every offset below: UNVERIFIED against our process.**
These are RVAs from *someone else's build*. Our image is
`0x7FF60FFA0000`, SizeOfImage `457,900,032`. Their largest RVA is
`0xBC81070` (197 MB), which does not fit the same layout. The *structure*
transfers; the *numbers* do not. Nothing here is promoted to MEASURED
until re-derived live.

---

## A. `working chams` — nothing to take, and that is the finding

2,104 lines, zero game-memory reads. No AOBs, no offsets, no decryption,
no entity list. It is a pure D3D12 pipeline cheat:

1. Hook `SetPipelineState` / `IASetIndexBuffer` / `IASetVertexBuffers` /
   `DrawIndexedInstanced` / `OMSetRenderTargets` / `RSSetViewports`.
2. Fingerprint each draw by `FNV1a(index-buffer VA, stride, startSlot, format)`
   into a 512-entry PSO registry (`rtexplorer.h`).
3. Match the player-mesh signature, rebuild that PSO with depth test
   disabled, re-bind it.

**Why it matters to us:** it renders players through walls *without ever
knowing what an entity is*. It is orthogonal to the entire crypto
problem — the GPU sees plaintext geometry no matter how the CPU-side
fields are keyed.

**Why it is not what we are doing:** it is a rendering hack, not reverse
engineering. It yields no field, no class, no address. It cannot tell you
health, team, or a bone position. Worth knowing the axis exists; not a
lead on the crypto map.

---

## B. `r6 unlockall` — the real material

This one contains **hand-recovered decryption routines**, transcribed
from IDA output (the dead `v128; // r10` register declarations are still
in place above every function). This is the first external corroboration
we have of the pointer chain's *shape*.

### B.1 The recurring `retaddr >> 33` term — IMPORTANT

Every decryptor ends with `+ (retaddr >> SHIFT)` where `SHIFT == 33`
(also written `>> 0x21`), and at the top of the namespace:

```cpp
auto retaddr = client;              // == module base
```

So the final addend is **`module_base >> 33`** — a constant per launch,
derived from the image base, *not* from the stack.

This bears on `SIEGE_CRYPTO_MAP.md §8`, where I recorded "stack-hashed
key selection" as the one mechanism an external process cannot reproduce.
That entry stands for the routine I actually observed, but **this source
shows the entity/pawn/actor chain does not use it** — it uses a
base-derived constant any external reader can compute. Worth re-checking
whether the routine I classified as stack-hashed is on this chain or
elsewhere.

For our base, `0x7FF60FFA0000 >> 33 = 0x3FFB0` — small, and a plausible
addend. **UNVERIFIED but cheap to test.**

### B.2 The chain

```
client + 0xBC81070  ->  deref  ->  +0x2D0   = GameManager
GameManager + 0xFB0/0xFB8       ->  EntityList (see B.3)
Entity  + 0x70                  ->  Pawn        (xor/add/xor + base>>33)
Pawn    + 0x18                  ->  Actor       (ROL 0x3B, xor, + base>>33)
Entity  + 0xF8                  ->  Replication (ROL 4, xor, xor, + base>>33)
Actor   + 0x1D0                 ->  OutlineComponent (add, sub, ROL 51, add, sub)
```

This answers the standing **GameManager** question structurally: it is a
single global pointer plus `0x2D0`, not something that needs an AOB.
The RVA is wrong for us; the shape is the lead.

### B.3 `GetEntityList` — byte-wise XOR unmasking, fully in the open

```cpp
v74.u64[0] = *(QWORD*)(GM + 0xFB0) + 0x3011412FAACD1A2B;
v74.u64[1] = *(QWORD*)(GM + 0xFB8) - 0x7357E5294088A93F;
// then three passes over the 16 bytes of v74, each XORing in:
//   pass 1: rolling key, starts 0xCB910B87C15C82CC, += 0x1D9704FD71E0AA5 per step
//   pass 2: constant 0xD2DD422B
//   pass 3: retaddr >> 33
return { v74.u64[0], v74.u64[1] & 0x3FFFFFFF };   // {list_ptr, count}
```

The `& 0x3FFFFFFF` count mask is a **near-match to our own measured
`entity+0xE0 & 0x1FFFFFFF`** — same idiom, one bit wider. Independent
corroboration that this engine stores counts masked in the high bits.

The odd `v7 += 7; v7++` stepping (7 bytes at a time through a 16-byte
value, then byte-wise past index 9) is the *unrolled form of an MBA
shuffle* — the fourth MBA variant shape, written out longhand.

### B.4 HEALTH — and why my sweeps missed it

```cpp
DamageComponentID = *(uint8_t*)(Actor + 0x232);
Damagecomponent   = *(uint64_t*)( *(uint64_t*)(Actor + 0xD8)
                                  + DamageComponentID * 8 );
Health            = *((DWORD*)Damagecomponent + 0x63) - 0x58;
```

Three things, in order of importance:

1. **`Actor + 0xD8` + a kind byte + `*8`.** This is *exactly* the
   component table we independently measured (`SIEGE_CRYPTO_MAP.md §6`).
   Two unrelated derivations, same structure. That section is corroborated.

2. **`0x232` is a component kind already in our range.** Our measured kind
   table spans `+0x1D8 .. +0x238`. `0x232` sits inside it and is *not*
   among the 33 kinds we resolved to a vtable — a kind we saw and skipped.

3. **Health is NOT encrypted. It is `stored - 0x58`.** Note `+ 0x63` is
   **DWORD-indexed**, so the byte offset is `0x63 * 4 = 0x18C`.

This explains the failure recorded in `SIEGE_CRYPTO_MAP.md §5`. All three
sweeps searched for plausible health *values*, and the pair sweep required
`cur <= max`. The stored value is `health + 0x58`: a 100-HP operator
stores `0x9C = 156`, which fails a test against plaintext maxima of
100/125/150.

**The §5 conclusion was over-generalised.** The measurement (three sweeps
empty) was correct; the inference — that gameplay fields are keyed and
value-shape search cannot work — extended one field block to the whole
entity. A bias of `+0x58` is not encryption, and is exactly what a
value-shape search *would* have found with a tolerance term. §5 should be
corrected rather than deleted; the reason it failed is the useful part.

### B.5 A second path to the skeleton

```cpp
uint64_t BoneInfo(uint64_t actor) {
    ComponentList = read(actor + 0xD8);
    return read(ComponentList + 8);     // component index 1 — no kind byte
}
```

We reach the skeleton via `entity + 0x229` -> kind -> `components[kind]`.
This source takes `components[1]` directly. Two routes to compare; if both
land on the same object in our process, that is a strong cross-check on
our resolver.

### B.6 Team, and a note on `getplayernames`

`team()` is ~250 lines of transcribed IDA with a two-branch tail doing
byte-shuffles and a `ROL4(..., 0xA)` on `*(DWORD*)(TeamCheckComp + 0xB0)`.
`getplayernames` returns `*(char*)(Replication + 0x790)` — a single char,
so it is the first byte of a string or a length, not a name. Neither is
worth transcribing before the chain is re-derived.

---

## C. What this changes

| `SIEGE_CRYPTO_MAP.md` | change |
|---|---|
| §5 "value-shape search cannot find gameplay fields" | **over-generalised — correct it.** Health is `stored - 0x58`. Keyed fields exist (the §5 field-block evidence still holds) but are not universal. |
| §6 component table | **corroborated independently.** Same `+0xD8` + kind-byte + `*8` shape. |
| §8 "stack-hashed, not externally reproducible" | **narrow it.** This chain uses `module_base >> 33`, externally computable. |
| §10 open: "which component owns health" | **candidate: kind `0x232`, field at byte `0x18C`, bias `-0x58`.** |

## D. Next, in order

1. Read `entity + 0x232` on a live entity; resolve `components[that]`;
   read DWORD at `+0x18C`; subtract `0x58`. Cheap, decisive.
2. Compare `components[1]` against our `entity+0x229` skeleton object.
3. Re-derive the GameManager global for *our* build — the structure is
   "one static pointer, deref, `+0x2D0`", so a scan for a static that
   derefs to an object whose `+0xFB0/+0xFB8` unmask into a plausible
   `{ptr, count}` is a targeted search, not a blind one.
4. Test whether `module_base >> 33` appears as an addend in the
   decryptors we have already emulated.
