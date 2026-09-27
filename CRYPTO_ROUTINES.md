# Crypto routine extraction — WORKING, verified against ground truth

Date 2026-09-19. Measured live, Siege pid 21800, base `0x7FF6279D0000`.

## The verification that matters

`crypto/decrypt.h` documents T7, derived BY HAND months ago from disassembly:

```
T7  plain = ROL64(enc, 4) - TLS[0x9800]
```

`/rt_at` recovers it automatically:

```
POST /rt_at {"rva":"0x42EB7B0"}
  forward   : (ROL64(enc, 0x4) - TLS[0x9800])
  inverse   : ROR64((plain + TLS[0x9800]), 0x4)
  tls_slots : 0x9800
  complete  : true    invertible : true
  field     : 0x1F0
  steps:
    0x42EB7B0  LOAD  input   mov r10, [rsp+0x1F0]
    0x42EB7D2  ROL   imm     rol r10, 0x04
    0x42EB7D6  SUB   tls     sub r10, rdx
```

Exact match, plus the INVERSE and the TLS slot, neither of which was given to
it. Two independent derivations agreeing is the strongest evidence available
short of running the game's own code.

The T7 site is at absolute `0x7FF62BCBB7D2` (RVA `0x42EB7D2`), found by
scanning for `49 C1 C2 04 49 29 D2` -- **exactly one site in the image**.

## What the routine extractor does

For any address in a crypto routine it reports:

- every OPERATION in order, with its operand SOURCE (imm / TLS / global)
- the TLS slots consumed, by offset
- the FORWARD formula, as text a human can check
- the INVERSE formula, derived by walking the ops backwards
- `complete` -- whether every operand was resolved
- `invertible` -- false when a lossy op (AND/OR/SHR/MUL) is present

A value dies on patch day. A routine can be re-derived, re-checked and
re-implemented, and is the only form in which a human can audit the tool.

## Three bugs found and fixed by testing against ground truth

**1. Forward-only tracking missed every key.**
The first version walked forward from the ciphertext load. But the key is
loaded AFTER the ciphertext:

```
mov r10, [rsp+0x1F0]     <- ciphertext
mov rdx, [rdx+0x9800]    <- key, loaded later
sub r10, rdx
```

so it reported `SUB reg` with an empty `tls_slots` -- a routine nobody can
reproduce. Fixed with a second pass that resolves register operands BACKWARDS
(scanning forward from the function entry and keeping the last write, because
x86 cannot be decoded in reverse).

**2. Backward discovery broke T7 (caught by regression).**
Adding "find the routine containing this address" made `/rt_at` walk back from
the ciphertext load to an EARLIER unrelated load, turning the exact T7 answer
into `~((enc + 0x100) + ?)`. A confident wrong answer.
Fixed: if the queried address is itself a memory load, it already IS the entry
-- do not walk back.

**3. `lea` misread as a TLS key load.**
`lea eax,[rcx-0x01]` was reported as `TLS[0xFFFFFFFF]`: the -1 displacement
sign-extended, and `rcx` had been wrongly flagged as a TLS block. Fixed two
ways -- `lea` computes an address and never reads memory, so it is excluded;
and TLS offsets are bounded to `(0, 0x40000)` since a block is tens of KB.
That site now honestly reports `(enc + ?)`, `complete=false`.

## Measured crypto surface

Probing 320 rotate sites (8 encodings of ROL/ROR on r64):

```
routines traced : 280
COMPLETE        : 85     (every operand resolved)
distinct TLS keys: 17
```

### Templates — the polymorphism, collapsed

The obfuscator emits the same logical operation many ways. Normalised to an
operation sequence they collapse to a short list:

| count | template |
|---|---|
| 21 | `LOAD-ROR` |
| 21 | `LOAD-ROL` |
| 14 | `LOAD-ADD` |
| 5 | `LOAD-ADD-XOR-ROL` |
| 4 | `LOAD-SUB-ROR-ADD` |
| 3 | `LOAD-ROR-ADD` |
| 3 | `LOAD-SUB-ROR` |
| 2 | `LOAD-ROL-ADD`, `LOAD-ROR-XOR-ROL`, `LOAD-ADD-ROL` |
| 1 | `LOAD-SUB`, `LOAD-XOR`, `LOAD-SHR`, `LOAD-ROL-SUB`, `LOAD-ADD-ROL-SUB`, `LOAD-ADD-XOR-ROL-ADD` |

**16 templates cover the whole sampled surface.** This is what defeats the
polymorphism: byte patterns see hundreds of unique sites, decoded operation
sequences see sixteen shapes.

### TLS key slots in use (all validated)

```
0x368 x5   0x3A8 x5   0x438 x4   0x390 x4   0x450 x3   0x430 x3
0x4B8 x2   0x240      0x440      0x3D0      0x220      0x3A0
0x200      0xEF0      0x228      0xB50      0x3C8
```

`0x368` corroborates `decrypt.h`, which documents T8 as reading
`[rax+0x368]` as a rotate count. Independent agreement again.

Multi-key routines exist and are handled:
`ROR64((enc - TLS[0x438]), TLS[0x390])` consumes TWO slots. Reporting only
the first is how a "working" decryptor produces garbage on the next field.

## Honest limits

- **85 of 280 complete.** The rest have at least one operand the straight-line
  resolver could not name -- typically a key loaded on one side of a branch.
  They are reported `complete:false` with `?` in the formula rather than
  guessed.
- The resolver does NOT follow branches. A guessed key silently yields wrong
  plaintext, so it refuses instead.
- `/rt_build` (whole-image scan) is built but too slow to be useful and
  times out. The per-site `/rt_at` path is the one that works; site discovery
  is better done with `/scan_aob` on the rotate encodings, as above.

## How to use it

```
1. find sites     POST /scan_aob {"pattern":"49 D3 CA","module_only":true}
2. extract        POST /rt_at    {"rva":"<site rva>"}
3. read the key   POST /tls_read {"offset":"0x9800"}
4. verify         POST /rt_verify{"rva":"<site rva>"}   (emulates it)
```

Step 2 accepts ANY address inside the routine, not just the entry -- it walks
back to find the ciphertext load.
