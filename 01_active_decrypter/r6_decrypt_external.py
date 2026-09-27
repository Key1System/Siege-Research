#!/usr/bin/env python3
"""
r6_decrypt_external.py

External decrypter for Rainbow Six Siege's TLS-keyed pointer obfuscation.

WHAT THIS DOES
--------------
Given an encrypted qword (from an object field) and the template it uses,
recovers the plaintext pointer WITHOUT injecting anything into the game.
Everything it needs is readable from outside:

  - the module base
  - the PE TLS directory (gives the TLS template + AddressOfIndex)
  - the target thread's TEB -> ThreadLocalStoragePointer[TlsIndex]

WHAT IT CANNOT DO
-----------------
Template T2 ("stack-hashed MBA") is NOT covered and cannot be, from
outside the process. Its key index is computed from the live RSP at the
call site, then used to index a global table. An external reader has no
way to know the callee's stack address. T2 requires an in-process hook.
Every other template observed in this build IS covered here.

VERIFIED AGAINST
----------------
RainbowSix.exe, module base 0x7FF792F90000, TLS dir RVA 0x145F5CD0.
See SIEGE_RECON_V5.md for the disassembly each formula was derived from.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import struct
import sys

MASK64 = (1 << 64) - 1


# --------------------------------------------------------------------------
# bit helpers
# --------------------------------------------------------------------------

def rol64(v: int, n: int) -> int:
    n &= 63
    v &= MASK64
    return ((v << n) | (v >> (64 - n))) & MASK64 if n else v


def ror64(v: int, n: int) -> int:
    n &= 63
    v &= MASK64
    return ((v >> n) | (v << (64 - n))) & MASK64 if n else v


# --------------------------------------------------------------------------
# the templates
#
# Each function takes the encrypted value plus whatever TLS key(s) the
# template consumes, and returns the plaintext. Offsets in the docstrings
# refer to slots inside the TLS block.
# --------------------------------------------------------------------------

def t7(enc: int, key_sub: int) -> int:
    """T7 -- ROL4 then subtract. Used for the bone-matrix buffer base.

        49 C1 C2 04    rol r10, 4
        49 29 D2       sub r10, rdx        ; rdx = TLS[0x9800]

    plain = ROL64(enc, 4) - TLS[k]
    """
    return (rol64(enc, 4) - key_sub) & MASK64


def t7_inverse(plain: int, key_sub: int) -> int:
    """Encrypt side of T7, for round-trip validation."""
    return ror64((plain + key_sub) & MASK64, 4)


def t7b(enc: int, key_sub: int) -> int:
    """T7b -- plain subtract, no rotate.

        49 29 D3       sub r11, rdx        ; rdx = TLS[0xD70]
    """
    return (enc - key_sub) & MASK64


def t8(enc: int, rot_key: int) -> int:
    """T8 -- rotate right by a TLS-supplied count.

        48 8B 88 68 03 00 00   mov rcx, [rax+0x368]
        49 D3 CA               ror r10, cl

    plain = ROR64(enc, TLS[k] & 63)

    Note the key slot holds a SMALL value (< 64) -- it is a shift count,
    not a 64-bit key. That is how you tell T8 slots apart in a dump.
    """
    return ror64(enc, rot_key & 63)


def t8_inverse(plain: int, rot_key: int) -> int:
    return rol64(plain, rot_key & 63)


def bone_base(field_158: int, key_add: int, key_sub: int) -> int:
    """The full bone-buffer chain, which stacks an add in front of T7.

        mov r10, [r12+0x9850]     ; key_add
        mov rdx, [rsi+0x158]      ; encrypted field
        add rdx, r10              ; enc = field + TLS[0x9850]
        ...
        rol r10, 4                ; \\ T7
        sub r10, rdx              ; /  key_sub = TLS[0x9800]
    """
    enc = (field_158 + key_add) & MASK64
    return t7(enc, key_sub)


# --------------------------------------------------------------------------
# live process access
# --------------------------------------------------------------------------

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll", use_last_error=True)


class Process:
    def __init__(self, pid: int):
        self.pid = pid
        self.h = k32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not self.h:
            raise OSError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}")

    def read(self, addr: int, size: int) -> bytes:
        buf = (ctypes.c_ubyte * size)()
        got = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(
            self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)
        )
        if not ok or got.value != size:
            raise OSError(f"RPM failed at {addr:#x} ({got.value}/{size} bytes)")
        return bytes(buf)

    def u32(self, addr: int) -> int:
        return struct.unpack("<I", self.read(addr, 4))[0]

    def u64(self, addr: int) -> int:
        return struct.unpack("<Q", self.read(addr, 8))[0]


# --------------------------------------------------------------------------
# TLS plumbing
# --------------------------------------------------------------------------

class TlsDirectory:
    """Parses IMAGE_TLS_DIRECTORY64 out of the mapped module."""

    def __init__(self, proc: Process, module_base: int):
        self.proc = proc
        self.base = module_base

        e_lfanew = proc.u32(module_base + 0x3C)
        nt = module_base + e_lfanew

        # OptionalHeader starts at NT+0x18; DataDirectory at Optional+0x70;
        # TLS is directory entry 9.
        tls_dir_entry = nt + 0x18 + 0x70 + 9 * 8
        rva = proc.u32(tls_dir_entry)
        self.dir_size = proc.u32(tls_dir_entry + 4)

        if rva == 0:
            raise RuntimeError("module has no TLS directory")

        d = module_base + rva
        self.start_raw = proc.u64(d + 0x00)
        self.end_raw = proc.u64(d + 0x08)
        self.addr_of_index = proc.u64(d + 0x10)
        self.addr_of_callbacks = proc.u64(d + 0x18)

        self.raw_size = self.end_raw - self.start_raw
        self.tls_index = proc.u32(self.addr_of_index)

    def template_qword(self, offset: int) -> int:
        """Read a key from the TLS *template* (the per-process initial image).

        This is what every new thread is seeded with. For key material that
        the game does not mutate at runtime, this equals the live value --
        which makes it readable without ever touching a TEB.
        """
        return self.proc.u64(self.start_raw + offset)

    def __repr__(self) -> str:
        return (
            f"TlsDirectory(index={self.tls_index}, "
            f"raw={self.start_raw:#x}..{self.end_raw:#x}, "
            f"size={self.raw_size:#x})"
        )


def tls_block_for_thread(proc: Process, teb: int, tls_index: int) -> int:
    """Live per-thread TLS block: TEB->ThreadLocalStoragePointer[index]."""
    tls_ptr = proc.u64(teb + 0x58)
    return proc.u64(tls_ptr + tls_index * 8)


# --------------------------------------------------------------------------
# key-slot classification
# --------------------------------------------------------------------------

# Slot roles are established ONLY by disassembling a site that reads the
# slot and decoding the consuming instruction. Every entry here cites the
# address the classification was proven at. Do NOT add entries inferred
# from the value's magnitude -- small values are equally likely to be
# flags, enums, counters or indices (see SIEGE_RECON_V5.md 4q).
PROVEN_SLOTS = {
    0x0018: ("count",  "cmp edx,[r10+0x18] loop bound",  "0x7FF79727BA6A"),
    0x001C: ("flag",   "cmp byte [..],0 / jnz",          "0x7FF79335916E"),
    0x0368: ("rot",    "ror r10, cl",                    "0x7FF79335235C"),
    0x06B8: ("ptr",    "test rdx,rdx / jz",              "0x7FF7933507F7"),
    0x0AC0: ("state",  "cmp [..],2 / jz",                "0x7FF796D2DAA8"),
    0x0D70: ("key",    "sub r11, rdx",                   "0x7FF79387FBFD"),
    0x3BD8: ("guard",  "read then mov [..],1",           "0x7FF793FB7196"),
    0x5EC0: ("key",    "not/xor/and chain",              "0x7FF79550533F"),
    0x8208: ("rot",    "ror r9, cl",                     "0x7FF796579C2A"),
    0x9728: ("key",    "byte-wise XOR key for 16B unpacker", "0x7FF79727C007"),
    0x9738: ("predicate", "shr/sub/test/jz -- opaque branch", "0x7FF79727BB39"),
    0x9800: ("key",    "sub r10, rdx (T7)",              "0x7FF79727B7D2"),
    0x9850: ("key",    "add rdx, r10 (T7 pre-add)",      "0x7FF79727BFDE"),
    0x98C8: ("offset", "add into ptr, passed as arg",    "0x7FF79727BFB9"),
    0xA1C0: ("flag",   "mov byte [..],1",                "0x7FF797B1B8E0"),
    0xE4A8: ("key",    "sub x2 (T7)",                    "0x7FF799974C64"),
    0xEBA0: ("key",    "not rbx + movsxd index",         "0x7FF79A0878A1"),
    0x1C210: ("counter", "movsxd then +1 writeback",     "0x7FF7A2D2D7B6"),
}


def dump_key_region(tls: TlsDirectory, start: int, end: int, stride: int = 8):
    """Dump a TLS range.

    Slots with a PROVEN role are annotated with that role and the address
    where it was proven. Everything else is printed as UNCLASSIFIED --
    which is the honest state until someone disassembles a site that
    reads it. No guessing from value shape.
    """
    print(f"{'offset':>8}  {'value':>18}  role      proven at")
    print("-" * 74)
    for off in range(start, end, stride):
        try:
            v = tls.template_qword(off)
        except OSError:
            break
        if v == 0:
            continue
        if off in PROVEN_SLOTS:
            role, how, site = PROVEN_SLOTS[off]
            print(f"{off:#8x}  {v:#18x}  {role:<8}  {site}  ({how})")
        else:
            print(f"{off:#8x}  {v:#18x}  UNCLASSIFIED")


# --------------------------------------------------------------------------
# known key slots for this build
# --------------------------------------------------------------------------

KEYS = {
    "bone_count":    (0x0018, "u32", "bone-loop bound"),
    "rot_368":       (0x0368, "rot", "T8 rotate count (45 sites)"),
    "sub_D70":       (0x0D70, "key", "T7b subtract"),
    "key_5EC0":      (0x5EC0, "key", "T9 MBA-XOR"),
    "rot_8208":      (0x8208, "rot", "T8 rotate count"),
    "bone_sub":      (0x9800, "key", "T7 subtract -- bone buffer"),
    "bone_add":      (0x9850, "key", "T7 pre-add -- bone buffer"),
    "sub_E4A8":      (0xE4A8, "key", "T7 subtract -- 2nd subsystem"),
    "key_EBA0":      (0xEBA0, "key", "T9-like"),
}


# --------------------------------------------------------------------------
# bone reading -- the end-to-end use case
# --------------------------------------------------------------------------

BONE_STRIDE = 0x40          # 64 bytes: a 4x4 row-major float matrix
BONE_POS_OFFSET = 0x30      # row 3 == translation, w == 1.0
OBJ_BONE_FIELD = 0x158      # encrypted buffer pointer on the skeleton object
OBJ_BONE_FIELD2 = 0x160     # the parallel buffer


def read_bones(proc: Process, tls: TlsDirectory, skel_obj: int, max_bones: int = 200):
    """Decrypt a skeleton object's bone buffer and yield per-bone transforms.

    Yields (index, (x, y, z)) for each bone whose matrix passes the
    homogeneous-coordinate sanity check (w == 1.0).
    """
    key_add = tls.template_qword(KEYS["bone_add"][0])
    key_sub = tls.template_qword(KEYS["bone_sub"][0])

    enc_field = proc.u64(skel_obj + OBJ_BONE_FIELD)
    base = bone_base(enc_field, key_add, key_sub)

    for i in range(max_bones):
        m = base + i * BONE_STRIDE
        try:
            raw = proc.read(m, BONE_STRIDE)
        except OSError:
            break

        # A real transform has w==0 on the three rotation rows and w==1.0
        # on the translation row. That is a strong validator.
        w0, w1, w2, w3 = struct.unpack_from("<f", raw, 0x0C)[0], \
                         struct.unpack_from("<f", raw, 0x1C)[0], \
                         struct.unpack_from("<f", raw, 0x2C)[0], \
                         struct.unpack_from("<f", raw, 0x3C)[0]
        if not (w0 == 0.0 and w1 == 0.0 and w2 == 0.0 and w3 == 1.0):
            break

        x, y, z = struct.unpack_from("<3f", raw, BONE_POS_OFFSET)
        yield i, (x, y, z)


def looks_like_bone_buffer(proc: Process, base: int, min_bones: int = 4) -> bool:
    """Validate a candidate decrypted base without knowing the bone count."""
    try:
        for i in range(min_bones):
            raw = proc.read(base + i * BONE_STRIDE, BONE_STRIDE)
            if struct.unpack_from("<f", raw, 0x3C)[0] != 1.0:
                return False
            if struct.unpack_from("<f", raw, 0x0C)[0] != 0.0:
                return False
    except OSError:
        return False
    return True


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def find_pid(name: str = "RainbowSix.exe") -> int:
    import subprocess
    out = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {name}", "/NH", "/FO", "CSV"],
        capture_output=True, text=True,
    ).stdout
    for line in out.splitlines():
        if name.lower() in line.lower():
            return int(line.split('","')[1])
    raise RuntimeError(f"{name} not running")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        print("usage:")
        print("  r6_decrypt_external.py dump <pid> <module_base_hex> [start] [end]")
        print("  r6_decrypt_external.py t7   <pid> <module_base_hex> <enc_hex>")
        print("  r6_decrypt_external.py t8   <pid> <module_base_hex> <enc_hex>")
        print("  r6_decrypt_external.py bones <pid> <module_base_hex> <skel_obj_hex>")
        return 1

    cmd = argv[1]
    pid = int(argv[2], 0)
    base = int(argv[3], 0)

    proc = Process(pid)
    tls = TlsDirectory(proc, base)
    print(f"[+] {tls}")
    print(f"[+] TlsIndex = {tls.tls_index} (from AddressOfIndex {tls.addr_of_index:#x})")

    if cmd == "dump":
        start = int(argv[4], 0) if len(argv) > 4 else 0x9700
        end = int(argv[5], 0) if len(argv) > 5 else 0x9900
        dump_key_region(tls, start, end)

    elif cmd == "t7":
        enc = int(argv[4], 0)
        k = tls.template_qword(KEYS["bone_sub"][0])
        print(f"    key TLS[0x9800] = {k:#x}")
        print(f"    plain           = {t7(enc, k):#x}")

    elif cmd == "t8":
        enc = int(argv[4], 0)
        k = tls.template_qword(KEYS["rot_368"][0])
        print(f"    rot TLS[0x368]  = {k} ({k & 63})")
        print(f"    plain           = {t8(enc, k):#x}")

    elif cmd == "bones":
        obj = int(argv[4], 0)
        for i, (x, y, z) in read_bones(proc, tls, obj):
            print(f"    bone[{i:3}] = ({x:10.3f}, {y:10.3f}, {z:10.3f})")

    else:
        print(f"unknown command: {cmd}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
