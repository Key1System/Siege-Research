# Trace — where the ENTITY_PATTERN leads

**Date:** 2026-09-16 · process `RainbowSix.exe` pid 24476 · base `0x7FF60FFA0000`
**Method:** internal tool (9998), Zydis disassembly, sandboxed emulation.

Starting point, supplied by the user:

```cpp
static constexpr const char* ENTITY_PATTERN =
    "60 00 00 00 00 ?? ?? ?? 02 00 00 00 ?? ?? 6C 00";
```

---

## 1. What the pattern actually matches — MEASURED

4 hits, module-only, 328 ms, complete (`timed_out:false`):

```
0x7FF616634FE1   +0x6694FE1
0x7FF617925427   +0x7985427
0x7FF61C7F39B0   +0xC8539B0
0x7FF61CB27293   +0xCB87293
```

All four are the **same instruction triple** against four different base
registers (`rbx`, `rbp`, `rsi`, `rcx`):

```asm
48 C7 4? 60 00 00 00 00   mov qword [reg+0x60], 0
C7 4? 68 02 00 00 00      mov dword [reg+0x68], 2
C6 4? 6C 00               mov byte  [reg+0x6C], 0
```

**It is not an entity signature. It is object-initialisation code.**
The `60`/`02`/`6C` in the pattern are displacement and immediate bytes of
three `mov`s, which is why it can only ever match executable memory. To
use the same idea as a heap finder you would search for *objects* whose
`+0x60 == 0`, `+0x68 == 2`, `+0x6C == 0` — the values, not the encoding.

## 2. The enclosing function — DERIVED (Zydis)

`0x7FF616634F10` (RVA `+0x6694F10`), prologue/epilogue matched:

```asm
push rdi ; push r14 ; push rbx ; sub rsp,0x20
mov  rdi, rdx                  ; arg2
mov  r14, rcx                  ; arg1
mov  r10, [0x7FF622D9CFC0]     ; allocator vtable -> 0x7FF62213F5E0
lea  rcx, [0x7FF622D9CFC0]     ; this = the allocator object itself
mov  edx, 0x70                 ; size  = 0x70
mov  r8d, 0x10                 ; align = 0x10
call [r10+0x10]                ; allocator->vtable[2]
mov  rbx, rax
test rax, rax
jnz  0x7FF61663508E            ; success -> lock inc [0x7FF622D9CFC8]
...
mov rax, rbx ; add rsp,0x20 ; pop rbx,r14,rdi ; ret
```

**It is a factory**: allocate 0x70 bytes, initialise, return the object.
The 0x70 size is consistent with the pattern's writes at `+0x60/+0x68/+0x6C`
— they fall in the last 0x10 bytes of the allocation.

## 3. The allocator — MEASURED

Static object at `0x7FF622D9CFC0` (RVA `+0x12DFCFC0`):

| offset | value | reading |
|---|---|---|
| `+0x00` | `0x7FF62213F5E0` | vtable (`[2]` = allocate) |
| `+0x08` | `0xA8F4D` | allocation counter (`lock inc`) |
| `+0x10` | `0x28230000` | pool base |
| `+0x18` | `0x200` | block size |
| `+0x30` | `0x58585858` | `'XXXX'` poison/guard |
| `+0x38` | `0x10000` | chunk size |

A general-purpose pool allocator — 692,557 allocations at sample time.
**Not entity-specific**, which is the important negative: this factory is
reached by anything allocating a 0x70 object.

## 4. The crypto detour — MEASURED, and a live example of mechanism 4

Three of the four sites are immediately followed by:

```asm
movabs rcx, 0x2D63B434F6063A3D    ; mask, identical at all three
add    rcx, [rip+…]               ; -> the SAME global, 0x7FF622DA4B10
mov    r10, rsp                   ; <-- the live stack pointer
and    r8,  0xE18E5003
or     r10, 0xE18E5003
add    r10, r8                    ; (x&y)+(x|y) == x+y   [MBA identity]
```

The global `0x7FF622DA4B10` (RVA `+0x12E04B10`) is **not a static key**:

```
t=0.0s  0xD0E328C46B8EC0BF
t=0.4s  0xD0E328C46BA3E7A8   delta +1,386,217
t=0.8s  0xD0E328C46B9A2A3D   delta   -638,315
t=2.4s  0xD0E328C46C45AE67   delta +9,848,405
```

High 32 bits constant (`D0E328C4`), low 32 bits churning in both
directions. A rotating value with a fixed identity half.

Because `rsp` is folded in, this is a concrete instance of **mechanism 4
(stack-hashed key selection)** from `SIEGE_CRYPTO_MAP.md §8` — the one
routine class an external reader cannot reproduce, since the index depends
on the stack pointer at the real call site.

## 5. Verdict

The pattern leads to a **generic pool allocator**, not to entities, not to
GameManager. It is a dead end for the entity hunt.

What it did yield, and is worth keeping:

- a confirmed live instance of the stack-hashed key routine, at three
  known sites, with its rotating global identified (`+0x12E04B10`);
- the game's general pool allocator (`+0x12DFCFC0`) and its vtable,
  which is a useful landmark for any future "who allocated this" question.

## 6. Correction to earlier work in this session

Instruction lengths were first decoded by hand, which produced three
"globals" at `+0x7CA0F22A`, `+0x7CE9E341`, `+0x7CE9DC40` — all beyond the
`0x1B4B0000` image, all unreadable. They were **fabricated** by
misjudging instruction boundaries; the real targets are `+0x12DF86C8` and
`+0x12DFCFC0`.

The failure was only caught because the invented addresses happened to be
unmapped. A wrong displacement that lands on mapped memory would have been
believed. **Hand-decoding x86 displacements is not acceptable here** — the
`/disasm` route now exists precisely so it never has to happen again.
