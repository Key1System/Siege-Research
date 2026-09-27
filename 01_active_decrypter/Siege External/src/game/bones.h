#pragma once
// game/bones.h — SkeletonComponent enumeration + per-bone reads.
//
// Scope (as of recon MD §16d/e/f):
//   - Enumerates SkeletonComponents by finding all locations that hold
//     the sub-entry vtable at slot+0x28, subtracting 0x28 to get the
//     component base.
//   - Reads the bone-slot array at SkelComp+0x50, stride 0x60 (96B).
//   - Slots are filtered by the flag byte at slot+0x1F == 0x0F.
//   - Per-slot: unit quaternion (16B) + partial translation (y,z).
//
// LIMITATIONS documented in recon §16e:
//   - These slots hold STATIC bind-pose / prop-attachment offsets, not
//     the per-frame ANIMATED pose. So drawing them will place markers
//     at fixed local offsets from the SkelComp origin, not at the
//     currently-animated bone position.
//   - Still useful for ESP because it lets us see WHERE THE COMPONENT IS
//     and place a numbered marker per slot for visual identification.
//
// The public API here is a single function `enumerate_and_read` that
// takes a live process handle and returns a vector of `Character`, each
// containing the SkelComp base, its associated CC (if we can match it),
// and the array of valid bone slots.

#include "../core/mem.h"
#include "../core/scan.h"
#include "../math/math.h"
#include "offsets.h"
#include <Windows.h>
#include <vector>
#include <cstdint>
#include <cmath>

namespace game {

struct Bone {
    int         index = 0;   // 0..N, position within the SkelComp's array
    math::Vec3  quat_xyz;    // rotation vector part (w discarded for now)
    float       quat_w = 0.f;
    // Local translation as stored in the slot. `x` is always 0 in
    // observed samples (see recon §16d).
    math::Vec3  local_trans;
    // Absolute address of the bone slot (for debug + click-to-inspect).
    uint64_t    slot_addr = 0;
    // Rolling motion score — updated by the scanner between reads.
    // Increases when the local_trans changes; decays on idle.
    // A "real animated" bone will sit at a nonzero score; static junk
    // sits near 0. Not populated by _read_character; populated by the
    // scanner after diffing against the previous frame's data.
    float       motion_score = 0.f;
};

struct Character {
    uint64_t          skel_comp = 0;  // SkeletonComponent base
    uint64_t          cc        = 0;  // matched CharacterController (0 if none)
    math::Vec3        world_pos;      // from CC+0x1D0 (if cc != 0)
    std::vector<Bone> bones;
};

// Internal: given a SkelComp base + optional CC list, build the
// Character (read bones + match to nearest CC). Shared by the enum
// and the from-cache path.
inline Character
_read_character(HANDLE h, uint64_t sc, const std::vector<uint64_t>& ccs)
{
    Character ch{};
    ch.skel_comp = sc;

    // Iterate every slot up to MAX_BONES. Instead of trusting a single
    // flag byte (which was too restrictive — see recon §16e), we accept
    // a slot if its translation floats are FINITE and within a plausible
    // bone-space range. Bone translations are typically < ~200 units;
    // pointer-aliased data reads as absurd magnitudes (1e20+) and gets
    // rejected.
    for (int i = 0; i < offsets::skel::MAX_BONES; ++i) {
        uint64_t slot = sc + offsets::skel::BONE_ARRAY_START
                          + (uint64_t)i * offsets::skel::BONE_STRIDE;

        Bone b{};
        b.index      = i;
        b.slot_addr  = slot;
        b.quat_xyz.x = core::read<float>(h, slot + offsets::skel::BONE_QUAT_X);
        b.quat_xyz.y = core::read<float>(h, slot + offsets::skel::BONE_QUAT_Y);
        b.quat_xyz.z = core::read<float>(h, slot + offsets::skel::BONE_QUAT_Z);
        b.quat_w     = core::read<float>(h, slot + offsets::skel::BONE_QUAT_W);
        b.local_trans.x = 0.f;
        b.local_trans.y = core::read<float>(h, slot + offsets::skel::BONE_TRANS_Y);
        b.local_trans.z = core::read<float>(h, slot + offsets::skel::BONE_TRANS_Z);

        // Strict filter for real bone entries:
        //   1) all four quat floats finite AND absolute value <= 1.01
        //   2) quat magnitude in [0.9, 1.1]   (unit quaternion)
        //   3) translations finite AND |t| < 5.0 (bones sit within a
        //      few units of parent — 500 was way too loose)
        //   4) not all-zero (rejects empty slots)
        auto fin = [](float f) { return std::isfinite(f); };
        if (!fin(b.quat_xyz.x) || !fin(b.quat_xyz.y) ||
            !fin(b.quat_xyz.z) || !fin(b.quat_w))          continue;
        if (std::abs(b.quat_xyz.x) > 1.01f ||
            std::abs(b.quat_xyz.y) > 1.01f ||
            std::abs(b.quat_xyz.z) > 1.01f ||
            std::abs(b.quat_w)     > 1.01f)                 continue;
        float mag = b.quat_xyz.x * b.quat_xyz.x
                  + b.quat_xyz.y * b.quat_xyz.y
                  + b.quat_xyz.z * b.quat_xyz.z
                  + b.quat_w     * b.quat_w;
        if (mag < 0.9f || mag > 1.1f)                       continue;
        if (!fin(b.local_trans.y) || !fin(b.local_trans.z)) continue;
        if (std::abs(b.local_trans.y) > 5.0f)               continue;
        if (std::abs(b.local_trans.z) > 5.0f)               continue;
        // Reject fully-zero (empty)
        if (b.local_trans.y == 0.f && b.local_trans.z == 0.f &&
            b.quat_xyz.x == 0.f && b.quat_xyz.y == 0.f &&
            b.quat_xyz.z == 0.f)                            continue;

        ch.bones.push_back(b);
    }

    // Match SkelComp to closest CC (see enumerate_skeletons for rationale).
    uint64_t best_cc = 0;
    uint64_t best_dist = UINT64_MAX;
    for (uint64_t cc : ccs) {
        uint64_t d = (cc > sc) ? (cc - sc) : (sc - cc);
        if (d < best_dist) { best_dist = d; best_cc = cc; }
    }
    ch.cc = best_cc;
    if (best_cc) {
        core::rpm(h, best_cc + offsets::cc::WORLD_POS,
                  &ch.world_pos, sizeof(ch.world_pos));
    }
    return ch;
}

// Fast path: build Character list from a pre-validated set of SkelComp
// addresses (e.g. read from disk cache). Skips the memory scan.
inline std::vector<Character>
skeletons_from_addrs(HANDLE h, const std::vector<uint64_t>& skels,
                     const std::vector<uint64_t>& ccs = {})
{
    std::vector<Character> out;
    out.reserve(skels.size());
    for (uint64_t sc : skels) {
        Character ch = _read_character(h, sc, ccs);
        if (!ch.bones.empty()) out.push_back(std::move(ch));
    }
    return out;
}

// Enumerate all live SkeletonComponents by scanning for the shared
// sub-entry vtable, then for each read the bone slot array. Fast: the
// scan is a full memory sweep for one qword value, then a few reads per
// hit.
//
// `vt_subentry` — computed via game::offsets::vt_skel_subentry(base).
// `ccs`          — optional CC list (from EntityCache); used to match
//                  each SkelComp to its CC by proximity. Pass empty to
//                  skip matching (CC field will be 0, world_pos zero).
inline std::vector<Character>
enumerate_skeletons(HANDLE h, uint64_t vt_subentry,
                    const std::vector<uint64_t>& ccs = {})
{
    std::vector<Character> out;

    // 1) Scan for all locations holding the sub-entry vtable value.
    auto hits = core::find_qword(h, 0x10000ULL, 0x7FFFFFFFFFFFULL,
                                  vt_subentry, /*limit=*/256,
                                  /*rw_only=*/true);
    if (hits.empty()) return out;

    for (uint64_t hit : hits) {
        if (hit < offsets::skel::SUBENTRY_VTABLE_OFFSET) continue;
        uint64_t sc = hit - offsets::skel::SUBENTRY_VTABLE_OFFSET;
        uint64_t self = core::read<uint64_t>(h, sc + 0x18);
        if (self != sc) continue;

        bool dup = false;
        for (const auto& c : out) if (c.skel_comp == sc) { dup = true; break; }
        if (dup) continue;

        Character ch = _read_character(h, sc, ccs);
        if (!ch.bones.empty()) out.push_back(std::move(ch));
    }

    return out;
}

// Extract just the SkelComp addresses from a Character list — useful
// for writing to the disk cache.
inline std::vector<uint64_t>
skel_addresses(const std::vector<Character>& chars) {
    std::vector<uint64_t> v;
    v.reserve(chars.size());
    for (const auto& c : chars) v.push_back(c.skel_comp);
    return v;
}

// Compose a bone's approximate world position from its SkelComp's CC:
//   world = cc_world_pos + (0, local_y, local_z)
// This is NOT the correct animated bone position (see §16e — bones are
// static bind-pose slots). It just places the marker at the character's
// world root plus the slot's stored local offset. Good enough for
// visualizing WHICH bones exist and their indices.
inline math::Vec3 approx_world(const Character& ch, const Bone& b) {
    return {
        ch.world_pos.x + b.local_trans.x,
        ch.world_pos.y + b.local_trans.y,
        ch.world_pos.z + b.local_trans.z,
    };
}

} // namespace game
