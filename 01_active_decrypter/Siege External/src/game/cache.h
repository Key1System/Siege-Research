#pragma once
#include "../core/mem.h"
#include "../core/scan.h"
#include "../math/math.h"
#include "offsets.h"
#include <Windows.h>
#include <vector>
#include <chrono>
#include <cstdio>
#include <string>
#include <algorithm>

namespace game {

struct Entity {
    uint64_t   cc   = 0;
    uint64_t   body = 0;
    math::Vec3 pos{};
    bool       valid = false;
};

// ── Disk cache ────────────────────────────────────────────────────
// Persist across launches. Cache holds:
//   - module base + vt_cc (invalidation keys)
//   - "hot arenas" — heap regions [base, size] that historically held CCs
//   - the CC addresses themselves
//
// On re-launch we validate each cached CC. Stale ones dropped. We STILL
// keep the hot arenas — even if every single CC has been recycled, we
// know WHERE to look, and a scan across ~10 MB of arenas is <100 ms.
//
// File format:
//   line 1: <module_base_hex> <vt_cc_hex>
//   line 2: <arena_count>
//   next N lines: <arena_base_hex> <arena_size_hex>
//   remaining lines: one CC address per line

struct Arena {
    uint64_t base = 0;
    uint64_t size = 0;
};

struct CcCache {
    std::vector<uint64_t> ccs;
    std::vector<Arena>    arenas;
};

inline std::string cc_cache_path() {
    char buf[MAX_PATH]{};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s = buf;
    auto slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s.resize(slash + 1);
    s += "entities.cache";
    return s;
}

inline CcCache cc_cache_read(uint64_t module_base, uint64_t vt_cc) {
    CcCache out{};
    FILE* f = fopen(cc_cache_path().c_str(), "r");
    if (!f) return out;
    uint64_t cached_base = 0, cached_vt = 0;
    if (fscanf(f, "%llx %llx",
               (unsigned long long*)&cached_base,
               (unsigned long long*)&cached_vt) != 2) {
        fclose(f);
        return out;
    }
    if (cached_base != module_base || cached_vt != vt_cc) {
        fclose(f);
        return out;
    }
    int arena_count = 0;
    if (fscanf(f, "%d", &arena_count) != 1) arena_count = 0;
    for (int i = 0; i < arena_count; ++i) {
        Arena a{};
        if (fscanf(f, "%llx %llx",
                   (unsigned long long*)&a.base,
                   (unsigned long long*)&a.size) != 2) break;
        out.arenas.push_back(a);
    }
    uint64_t addr = 0;
    while (fscanf(f, "%llx", (unsigned long long*)&addr) == 1) out.ccs.push_back(addr);
    fclose(f);
    return out;
}

inline void cc_cache_write(uint64_t module_base, uint64_t vt_cc,
                            const std::vector<Arena>& arenas,
                            const std::vector<uint64_t>& ccs) {
    FILE* f = fopen(cc_cache_path().c_str(), "w");
    if (!f) return;
    fprintf(f, "%llx %llx\n",
            (unsigned long long)module_base,
            (unsigned long long)vt_cc);
    fprintf(f, "%d\n", (int)arenas.size());
    for (const auto& a : arenas) {
        fprintf(f, "%llx %llx\n",
                (unsigned long long)a.base, (unsigned long long)a.size);
    }
    for (uint64_t a : ccs) fprintf(f, "%llx\n", (unsigned long long)a);
    fclose(f);
}

class EntityCache {
public:
    static bool is_real_cc(HANDLE h, uint64_t cand,
                           uint64_t vt_cc, uint64_t vt_body)
    {
        if (core::read<uint64_t>(h, cand + offsets::cc::VTABLE) != vt_cc)
            return false;
        uint64_t body = core::read<uint64_t>(h, cand + offsets::cc::BODY_PTR);
        if (!body) return false;
        if (core::read<uint64_t>(h, body + offsets::body::VTABLE) != vt_body)
            return false;
        return true;
    }

    // Fast-path validation of a list of cached CC addresses.
    // Drops stale ones. Returns count that survived.
    size_t install_from_cache(HANDLE h, const std::vector<uint64_t>& cached,
                              uint64_t vt_cc, uint64_t vt_body)
    {
        entities_.clear();
        for (uint64_t cc : cached) {
            if (!is_real_cc(h, cc, vt_cc, vt_body)) continue;
            Entity e{};
            e.cc = cc;
            e.body = core::read<uint64_t>(h, cc + offsets::cc::BODY_PTR);
            core::rpm(h, cc + offsets::cc::WORLD_POS, &e.pos, sizeof(e.pos));
            e.valid = true;
            entities_.push_back(e);
        }
        last_rebuild_ = std::chrono::steady_clock::now();
        return entities_.size();
    }

    // Scan the given regions in parallel for vt_cc, validate each hit.
    // Returns { new entities, hot arenas that yielded ANY valid CC }.
    struct RebuildResult {
        std::vector<Arena> hot_arenas;
        uint64_t           scan_ms      = 0;
        uint64_t           scanned_bytes = 0;
    };

    RebuildResult rebuild_in_regions(
        HANDLE h,
        uint64_t vt_body,
        uint64_t vt_cc,
        const std::vector<MEMORY_BASIC_INFORMATION>& regs,
        int workers = 4)
    {
        entities_.clear();
        RebuildResult rr{};

        // vt_cc is very common (appears in 2000+ places as a shared field).
        // Ask for lots of candidates, then filter.
        auto s = core::find_qword_mt(h, regs, vt_cc, /*limit=*/16384, workers);
        rr.scan_ms       = s.scan_ms;
        rr.scanned_bytes = s.scanned_bytes;

        for (uint64_t c : s.hits) {
            if (c < offsets::cc::VTABLE) continue;
            uint64_t cc = c - offsets::cc::VTABLE;
            if (!is_real_cc(h, cc, vt_cc, vt_body)) continue;
            // Dedup
            bool dup = false;
            for (auto& e : entities_) if (e.cc == cc) { dup = true; break; }
            if (dup) continue;

            Entity e{};
            e.cc = cc;
            e.body = core::read<uint64_t>(h, cc + offsets::cc::BODY_PTR);
            core::rpm(h, cc + offsets::cc::WORLD_POS, &e.pos, sizeof(e.pos));
            e.valid = true;
            entities_.push_back(e);
        }

        // From the hot regions reported by the scanner, keep only those
        // that contained a REAL CC (not just an incidental vt_cc match).
        for (const auto& hr : s.hot_regions) {
            bool has_real_cc = false;
            for (const auto& e : entities_) {
                if (e.cc >= hr.base && e.cc < hr.base + hr.size) {
                    has_real_cc = true;
                    break;
                }
            }
            if (has_real_cc) rr.hot_arenas.push_back({ hr.base, hr.size });
        }

        last_rebuild_ = std::chrono::steady_clock::now();
        return rr;
    }

    // Two-tier rebuild:
    //   1. Scan the cached hot arenas first (usually 10-50 MB, ~50 ms).
    //   2. If nothing turns up (arenas moved), fall back to full-space.
    RebuildResult rebuild(
        HANDLE h,
        uint64_t vt_body,
        uint64_t vt_cc,
        const std::vector<Arena>& hint_arenas,
        int workers = 4)
    {
        // Try the hinted arenas first.
        if (!hint_arenas.empty()) {
            std::vector<MEMORY_BASIC_INFORMATION> hinted;
            for (const auto& a : hint_arenas) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(h, (LPCVOID)a.base, &mbi, sizeof(mbi))
                    != sizeof(mbi)) continue;
                if (mbi.State != MEM_COMMIT) continue;
                if (mbi.Type != MEM_PRIVATE) continue;
                if (!(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
                hinted.push_back(mbi);
            }
            auto rr = rebuild_in_regions(h, vt_body, vt_cc, hinted, workers);
            if (!entities_.empty()) {
                if (core::scan_debug().load()) {
                    printf("[Cache] hinted rebuild: %zu entities, %llu MB, %llu ms\n",
                           entities_.size(),
                           (unsigned long long)(rr.scanned_bytes >> 20),
                           (unsigned long long)rr.scan_ms);
                    fflush(stdout);
                }
                return rr;
            }
            if (core::scan_debug().load()) {
                printf("[Cache] hint miss — falling back to full range\n");
                fflush(stdout);
            }
        }
        // Fallback — full private-RW enumeration.
        auto full_regs = core::scannable_regions(h, 0x10000ULL, 0x7FFFFFFFFFFFULL);
        auto rr = rebuild_in_regions(h, vt_body, vt_cc, full_regs, workers);
        if (core::scan_debug().load()) {
            printf("[Cache] full rebuild: %zu entities, %llu MB, %llu ms\n",
                   entities_.size(),
                   (unsigned long long)(rr.scanned_bytes >> 20),
                   (unsigned long long)rr.scan_ms);
            fflush(stdout);
        }
        return rr;
    }

    // Per-frame: re-read world pos from each cached CC. If a CC has
    // become invalid (address recycled to a non-CC object), mark it as
    // needing rebuild.
    void refresh_positions(HANDLE h, uint64_t vt_cc, uint64_t vt_body,
                           bool& out_needs_rebuild)
    {
        out_needs_rebuild = false;
        for (auto& e : entities_) {
            if (!e.valid) continue;
            // Cheap validity check: vt @ CC+0x10 still == vt_cc.
            uint64_t vt = core::read<uint64_t>(h, e.cc + offsets::cc::VTABLE);
            if (vt != vt_cc) {
                e.valid = false;
                out_needs_rebuild = true;
                continue;
            }
            math::Vec3 p{};
            if (core::rpm(h, e.cc + offsets::cc::WORLD_POS, &p, sizeof(p))) {
                e.pos = p;
            } else {
                e.valid = false;
                out_needs_rebuild = true;
            }
        }
    }

    std::vector<uint64_t> cc_addresses() const {
        std::vector<uint64_t> v;
        v.reserve(entities_.size());
        for (const auto& e : entities_) v.push_back(e.cc);
        return v;
    }

    const std::vector<Entity>& entities() const { return entities_; }

private:
    std::vector<Entity> entities_;
    std::chrono::steady_clock::time_point last_rebuild_{};
};

} // namespace game
