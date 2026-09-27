#pragma once
// game/bones_cache.h — disk cache for SkeletonComponent addresses.
//
// Mirror of cache.h but for SkelComps. Format is a plaintext file next
// to the exe called `skeletons.cache`:
//
//   line 1: <module_base_hex> <vt_subentry_hex>
//   remaining lines: one SkelComp address per line
//
// On load: validate each cached SkelComp by checking that
//   [addr + 0x28] == vt_subentry  AND  [addr + 0x18] == addr (self-ref).
// Stale entries are silently dropped.
//
// On save: overwrite with whatever the current in-memory list is.
//
// Keying by module_base means a game restart (ASLR shifts) invalidates
// the whole file automatically. Within a single game session the SkelComp
// addresses persist across ESP tool restarts, so re-launching Siege
// External doesn't force a full rescan.

#include "../core/mem.h"
#include "offsets.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdint>

namespace game {

inline std::string skel_cache_path() {
    char buf[MAX_PATH]{};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s = buf;
    auto slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s.resize(slash + 1);
    s += "skeletons.cache";
    return s;
}

// Load SkelComp addresses from disk. Returns an empty vector if the
// cache is missing, mismatched, or all entries were stale.
inline std::vector<uint64_t>
skel_cache_read(HANDLE h, uint64_t module_base, uint64_t vt_subentry)
{
    std::vector<uint64_t> out;
    FILE* f = fopen(skel_cache_path().c_str(), "r");
    if (!f) return out;
    uint64_t cached_base = 0, cached_vt = 0;
    if (fscanf(f, "%llx %llx",
               (unsigned long long*)&cached_base,
               (unsigned long long*)&cached_vt) != 2)
    {
        fclose(f);
        return out;
    }
    if (cached_base != module_base || cached_vt != vt_subentry) {
        fclose(f);
        return out;
    }
    uint64_t addr = 0;
    std::vector<uint64_t> raw;
    while (fscanf(f, "%llx", (unsigned long long*)&addr) == 1)
        raw.push_back(addr);
    fclose(f);

    // Validate each: [addr + 0x28] == vt_subentry && [addr + 0x18] == addr.
    for (uint64_t a : raw) {
        uint64_t vt = core::read<uint64_t>(
            h, a + offsets::skel::SUBENTRY_VTABLE_OFFSET);
        if (vt != vt_subentry) continue;
        uint64_t self = core::read<uint64_t>(h, a + 0x18);
        if (self != a) continue;
        out.push_back(a);
    }
    return out;
}

inline void skel_cache_write(uint64_t module_base, uint64_t vt_subentry,
                              const std::vector<uint64_t>& skels)
{
    FILE* f = fopen(skel_cache_path().c_str(), "w");
    if (!f) return;
    fprintf(f, "%llx %llx\n",
            (unsigned long long)module_base,
            (unsigned long long)vt_subentry);
    for (uint64_t a : skels) fprintf(f, "%llx\n", (unsigned long long)a);
    fclose(f);
}

} // namespace game
