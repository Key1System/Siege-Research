// crypto/skel_probe.h — SkeletonDescriptor resolver via in-process
// trampoline into the game's own AcquireSkeletonDescriptor.
//
// The whole point:
//   Given a live entity address, invoke the game's own
//   sub_7FF6FE391120(entity, 1) in-process. That function walks the
//   T2-encrypted state internally (using the real stack + TLS keys),
//   populates a fresh SkeletonDescriptor slot in the ms_SkeletonDescriptors
//   pool, and writes the slot handle back to entity+0x1B0.
//
//   Once the call returns, we can read entity+0x1B0 (still a handle),
//   OR chase from entity+0x2A8 → SkeletonComponent → descriptor.
//   Either way, no MBA symbolic execution needed — the game did the
//   decrypt for us.
//
// This is READ-ONLY as far as the game is concerned: AcquireSkeleton
// runs the same logic it would when the anim system polls a bone; we're
// just piggy-backing on its result.
//
// Safety:
//   - We call the fn on our own thread, but the code uses TlsIndex
//     which is process-global — so any live TLS block works.
//   - The internal slot-allocator path uses _InterlockedCompareExchange
//     for the descriptor handle — safe under concurrency.
//   - We only wrap the call in an SEH __try/__except so a bad entity
//     pointer doesn't kill the DLL.
#pragma once
#include "types.h"
#include <cstdint>

namespace crypto::skel {

// Install trampolines. Resolves the game function addresses from RVAs
// baked at build time. Called from crypto::init.
bool install(uint64_t module_base) noexcept;

struct AcquireResult {
    bool     ok               = false;
    uint64_t entity           = 0;   // input (echo)
    uint64_t skel_component   = 0;   // entity[+0x2A8]
    uint64_t desc_slot_handle = 0;   // entity[+0x1B0]  (encrypted qword)
    uint64_t desc_key_seed    = 0;   // entity[+0x1A8]
    uint32_t desc_epoch       = 0;   // low 32 bits of handle
    uint32_t desc_slot_index  = 0;   // bits 33..47 of handle
};

// Invoke AcquireSkeletonDescriptor(entity, flag=1) on the given entity.
// Reads the descriptor state fields OUT of the entity after the call.
// If entity is null or the SEH wrap catches, returns { ok=false }.
AcquireResult acquire(uint64_t entity) noexcept;

// Diagnostic: for a given SkeletonComponent, dump N bytes at
// bone_slot[+0x50..+0x50+N*0x60] and interpret them as bone slots
// (quat + local translation). Reads live memory — no crypto.
struct BoneSample {
    int   index;
    float qx, qy, qz, qw;
    float trans_x, trans_y, trans_z;
    uint8_t flag_byte;  // +0x1F
};

// Returns up to `max_bones` bone samples from a SkelComp.
// Filters out slots whose flag byte != 0x0F.
size_t read_bones(uint64_t skel_component,
                   BoneSample* out, size_t max_bones) noexcept;

} // namespace crypto::skel
