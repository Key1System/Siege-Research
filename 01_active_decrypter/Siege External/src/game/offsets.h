#pragma once
#include <cstdint>

namespace game::offsets {

// IDB image base + vtable address from the recon MD §0/§11. The RVA
// (address - base) is stable across every launch — only the loaded
// base moves with ASLR. Derive the live vtable each session as
//   live_vt = current_base + VT_HKNP_CHARACTER_BODY_RVA
static constexpr uint64_t IDB_IMAGE_BASE         = 0x7FF6FBEB0000ULL;
static constexpr uint64_t IDB_VT_HKNP_CHAR_BODY  = 0x7FF70BC248E0ULL;
static constexpr uint64_t VT_HKNP_CHARACTER_BODY_RVA =
    IDB_VT_HKNP_CHAR_BODY - IDB_IMAGE_BASE;   // 0x0FD748E0

// RigidBody/CharacterController vtable RVA — matches recon MD §5.1
// (IDA 0x7FF70BCBC7D0 - IDB base 0x7FF6FBEB0000 = 0x0FE0C7D0). Live-
// verified 2026-07-17 in a fresh session: base 0x7FF6D5B10000 + this
// RVA = 0x7FF6E591C7D0, which is the vtable pointer at CC+0x10.
static constexpr uint64_t VT_RIGIDBODY_CC_RVA = 0x0FE0C7D0ULL;

// SkeletonComponent sub-entry vtable at SkelComp+0x28.
// Live 0x7FF6E28B34F0 with base 0x7FF6D5B10000 → RVA 0x0CDA34F0.
static constexpr uint64_t VT_SKEL_SUBENTRY_RVA = 0x0CDA34F0ULL;

inline uint64_t vt_hknp_character_body(uint64_t module_base) {
    return module_base + VT_HKNP_CHARACTER_BODY_RVA;
}
inline uint64_t vt_rigidbody_cc(uint64_t module_base) {
    return module_base + VT_RIGIDBODY_CC_RVA;
}
inline uint64_t vt_skel_subentry(uint64_t module_base) {
    return module_base + VT_SKEL_SUBENTRY_RVA;
}

// hknpCharacterRigidBody fields (recon MD §2.3)
namespace body {
    static constexpr int VTABLE     = 0x00;
    static constexpr int BODY_ID    = 0x18;  // qword: {gen:32 | id:32}
    static constexpr int MANAGER    = 0x30;
}

// RigidBody / CharacterController wrapper.
// Live-verified 2026-07-17 against 4 running CCs (base 0x7FF6D5B10000).
// The recon MD §5.2 was WRONG about WORLD_POS: it claimed +0xA0 (row 3
// of the 4×4 at +0x70), but that region actually holds a quaternion
// identity. The real world Vec3 lives at +0x1D0. Confirmed on 4 bots
// standing in a line at Y=20.4, Z=31.3, X in {53,55,57,59}.
namespace cc {
    static constexpr int BODY_PTR        = 0x00; // -> hknpCharacterRigidBody
    static constexpr int VTABLE          = 0x10; // == vt_rigidbody_cc
    static constexpr int VTABLE2         = 0x18;
    static constexpr int DAMPING         = 0xF0; // (60.0f, 18.5f) pair
    static constexpr int WORLD_POS       = 0x1D0; // Vec3 xyz — LIVE-VERIFIED
    static constexpr int BODY_ID_QWORD   = 0xF8;
}

// SkeletonComponent — recon MD §16d.
//   Sub-entry vtable at +0x28 (used to enumerate via find_qword)
//   Bone-slot array starts at +0x50, stride 0x60 (96 bytes/slot)
//   Byte at slot+0x1F == 0x0F ⇒ real transform slot
//                     == 0x03 ⇒ ASCII name entry (skip)
//                     == 0x00 ⇒ empty / other
namespace skel {
    static constexpr int SUBENTRY_VTABLE_OFFSET = 0x28;    // for enumeration
    static constexpr int BONE_ARRAY_START       = 0x50;
    static constexpr int BONE_STRIDE            = 0x60;    // 96 bytes
    static constexpr int MAX_BONES              = 100;     // safe upper bound

    // Per-bone fields (offsets relative to slot base):
    static constexpr int BONE_QUAT_X            = 0x00;
    static constexpr int BONE_QUAT_Y            = 0x04;
    static constexpr int BONE_QUAT_Z            = 0x08;
    static constexpr int BONE_QUAT_W            = 0x0C;
    // +0x10 = 0.0f pad (SIMD alignment)
    static constexpr int BONE_TRANS_Y           = 0x14;
    static constexpr int BONE_TRANS_Z           = 0x18;
    static constexpr int BONE_FLAG_BYTE         = 0x1F;    // 0x0F = valid transform
    static constexpr uint8_t BONE_FLAG_VALID    = 0x0F;
}

} // namespace game::offsets
