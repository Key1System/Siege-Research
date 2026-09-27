#pragma once
#include <cstdint>

/*
 * ============================================================================
 *  r6_offsets.h — All patch-specific game offsets in one place
 * ============================================================================
 *
 *  This build (Y9S5+) abandoned the per-thread TLS encryption scheme. The
 *  GameManager pointer is now found by:
 *    1. AOB-scanning the .text section for a unique 19-byte instruction
 *    2. RIP-relative decoding of the disp32 at hit+7
 *    3. Dereferencing the resulting static slot
 *
 *  The active world camera (VP matrix + camera position) lives on a
 *  SEPARATE singleton found via a unique data AOB pattern in heap.
 *
 *  When R6S updates, you ONLY need to change the values in this file.
 *  The chain itself (AOB hit → static slot → GM → ELC) has been stable
 *  across many patches.
 *
 *  All offsets verified live via Cheat Engine MCP.
 * ============================================================================
 */

namespace r6::offsets {

    // ── Patch identifier ────────────────────────────────────────────────
    inline constexpr const char* PATCH_VERSION = "Y9S5-AOB+post-update";

    // ────────────────────────────────────────────────────────────────────
    //  GAMEMANAGER — found via AOB scan in .text
    // ────────────────────────────────────────────────────────────────────
    //
    //   Pattern (19 bytes, unique single hit in the whole .text section):
    //     48 83 EC 38 4C 8B 0D ?? ?? ?? ?? 41 83 B9 ?? ?? 00 00 00
    //
    //   Disassembly at the hit:
    //     sub  rsp, 38h
    //     mov  r9, cs:qword_<static_slot>     ← rip+disp32 at hit+7..11
    //     cmp  dword ptr [r9+2D88h], 0
    //
    //   Resolution:
    //     rel32   = *(int32_t*)(hit + 7)
    //     slotPtr = (hit + 11) + rel32
    //     gameMgr = *slotPtr
    //
    //   Verified across many builds — RVA of the .text hit moves when Ubi
    //   recompiles (current build: 0x4ADFCD0). Pattern itself is stable.
    inline constexpr const char* GM_AOB_PATTERN =
        "48 83 EC 38 4C 8B 0D ?? ?? ?? ?? 41 83 B9 ?? ?? 00 00 00";
    inline constexpr int GM_DISP_OFF = 7;   // offset of disp32 from hit
    inline constexpr int GM_RIP_OFF  = 11;  // offset of next-insn from hit

    // ────────────────────────────────────────────────────────────────────
    //  GAMEMANAGER struct layout
    // ────────────────────────────────────────────────────────────────────
    //   +0x00  vtable (RainbowSix.exe .rdata)
    //   +0x08  size/flag word — NOT a pointer
    //   +0x10  ELC pointer (Entity List Container)
    inline constexpr uint64_t GM_VTABLE        = 0x00;
    inline constexpr uint64_t GM_ELC_PTR       = 0x10;

    // ────────────────────────────────────────────────────────────────────
    //  ENTITY LIST CONTAINER (ELC) layout
    // ────────────────────────────────────────────────────────────────────
    //   Each slot is 0x40 bytes:
    //     slot[+0x00]  ENT1 — the entity object (vtable selects gameplay role)
    //     slot[+0x08]  ENT2 — the transform_obj. Read pos at ENT2+0x90.
    inline constexpr uint64_t ELC_STRIDE       = 0x40;
    inline constexpr uint64_t ELC_ENT1         = 0x00;
    inline constexpr uint64_t ELC_ENT2         = 0x08;
    inline constexpr int      ELC_MAX_SLOTS    = 4096;
    inline constexpr int      ELC_NULL_LIMIT   = 64;  // stop after N consecutive null slots

    // ────────────────────────────────────────────────────────────────────
    //  TRANSFORM_OBJ layout (= ENT2 = ELC slot+0x08)
    // ────────────────────────────────────────────────────────────────────
    //   +0x40  Right basis  (3 floats, unit length)
    //   +0x50  Up basis     (3 floats)
    //   +0x60  Forward      (3 floats)
    //   +0x70  R/U/F duplicated again (some builds)
    //   +0x90  Position     (X, Y, Z, w=1.0)   ← THIS is what ESP wants
    inline constexpr uint64_t T_BASIS_RIGHT    = 0x40;
    inline constexpr uint64_t T_BASIS_UP       = 0x50;
    inline constexpr uint64_t T_BASIS_FWD      = 0x60;
    inline constexpr uint64_t T_POSITION       = 0x90;  // vec4

    // ────────────────────────────────────────────────────────────────────
    //  VIEW TRANSLATION SINGLETON — found via parallel heap scan
    // ────────────────────────────────────────────────────────────────────
    //   Discovery is a single-path scan in r6_decrypt.h:
    //   `parallel_heap_scan_for_singleton(module_base + VT_VTABLE_RVA)`.
    //
    //   It enumerates committed RW regions via VirtualQueryEx, then
    //   reads each region with N worker threads / 16 MB chunks, looking
    //   for the qword that equals the VT vtable address. The vtable sits
    //   at offset 0 of the singleton, so a hit IS the singleton.
    //
    //   After resolution:
    //     view_translation + 0x1D0  = camera position (vec4)
    //     view_translation + 0x290  = 4x4 view-projection matrix
    //                                  (column-major float[4][4]).
    //
    //   FOV is BAKED INTO the matrix — no separate FOV scalar needed.
    //
    //   When Ubi patches: re-verify VT_VTABLE_RVA via Cheat Engine MCP
    //   and update it here. Nothing else in this file needs to change.
    inline constexpr uint64_t VT_CAMERA_POS    = 0x1D0;  // vec4
    inline constexpr uint64_t VT_VP_MATRIX     = 0x290;  // 4x4 col-major
    inline constexpr uint64_t VT_VTABLE_RVA    = 0x13BFA0A0;

    // ────────────────────────────────────────────────────────────────────
    //  Entity ID for stable identification across frames
    // ────────────────────────────────────────────────────────────────────
    //   Sequential u32 handles allocated per match. Useful for tracking
    //   entities even when their pointer position in the ELC moves.
    inline constexpr uint64_t ENT_ID           = 0x60;

    // ────────────────────────────────────────────────────────────────────
    //  ENT1 player-detection fields (matches reference dxrainbowinternal)
    // ────────────────────────────────────────────────────────────────────
    //   These fields exist on every ENT1 in the ELC; for ACTUAL player
    //   pawns the values fall in well-defined ranges, while doors / props
    //   / gadgets have garbage there. Far more reliable than vtable
    //   matching because it works regardless of which subclass the player
    //   pawn happens to be in any given build.
    //
    //   ENT1_ROLE_ID @ +0x1C: int32. For players this is in [1, 999].
    //                        Random map objects are 0 or huge sentinel values.
    //
    //   ENT1_STATUS_BF @ +0xB0: u64 packed flags. Reference cheat extracts:
    //     byte3 = (bf >> 24) & 0xFF
    //     byte4 = (bf >> 32) & 0xFF
    //     byte3 == 0xFA  -> DEAD (corpse, just died)
    //     byte4 == 0x80  -> DEAD (disconnected/replaced)
    //     byte4 == 0x02  -> TEAM (squadmate)
    //     byte4 == 0x00  -> LOCAL (you)
    //     anything else  -> ALIVE enemy
    inline constexpr uint64_t ENT1_ROLE_ID     = 0x1C;
    inline constexpr uint64_t ENT1_STATUS_BF   = 0xB0;

    // ── Stable per-player UID (post-update build) ────────────────────────
    //
    //   ENT1+0x08 is a packed qword where the HIGH 32 bits hold a unique
    //   per-player hash that is:
    //     * unique across players in the same match
    //     * stable for the session for a given player
    //     * hash-shaped (high entropy) on real avatars; on system filler
    //       objects (LocalPlayer-wrapper bot slot, null sentinel) it is
    //       either 0 or a bit-patterned value like 0x49249200.
    //
    //   We use it as the dedup key when the same player appears in
    //   multiple ELC slots (operator-avatar + embedded shadow + alias).
    //   Read with: rpm<uint32_t>(ent1 + ENT1_UID_HI32).
    inline constexpr uint64_t ENT1_UID_HI32    = 0x0C;

    // ────────────────────────────────────────────────────────────────────
    //  Player-class vtable RVAs (verified live across many sessions —
    //  see siege/FINDINGS.md §2). These are the ENT1 vtables that
    //  represent operator/player entities in the ELC. Everything else
    //  in the ELC is doors / weapons / gadgets / props — same transform
    //  layout but not what we want to box.
    // ────────────────────────────────────────────────────────────────────
    // Post-update build (current): vtables shifted by +0x70F2C8 from
    // the previous (commented) values. ALL FOUR verified live to hold
    // valid function-pointer first qwords.
    inline constexpr uint64_t PLAYER_VT_RVAS[] = {
        0x13A9E078,  // operator avatar — the rendered character (was 0x1338EDB0)
        0x13A9E178,  // player network slot                      (was 0x1338EEB0)
        0x13A9E0F8,  // LocalPlayer wrapper (you)                (was 0x1338EE30)
        0x13A9E278,  // legacy player vtable                     (was 0x1338EFB0)
    };
    inline constexpr int PLAYER_VT_COUNT =
        sizeof(PLAYER_VT_RVAS) / sizeof(PLAYER_VT_RVAS[0]);

    // ────────────────────────────────────────────────────────────────────
    //  Pointer validation bounds
    // ────────────────────────────────────────────────────────────────────
    inline constexpr uint64_t USERMODE_LO      = 0x10000ULL;
    inline constexpr uint64_t USERMODE_HI      = 0x7FFFFFFFFFFFULL;

} // namespace r6::offsets
