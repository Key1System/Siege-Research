#pragma once
#include "../core/scan.h"
#include "../core/mem.h"
#include "../math/math.h"
#include <Windows.h>
#include <cstdio>
#include <string>

namespace game {

// R6S ViewData layout (constant across builds — verified via CE table):
//   ViewData + 0x190 = Vec3 camera position
//   ViewData + 0x250 = 4x4 view-projection matrix (row-major)
//   ViewData + 0x2A4 = constant-float signature we scan for
static constexpr int64_t VD_CAM_POS_OFF   = 0x190;
static constexpr int64_t VD_VIEW_PROJ_OFF = 0x250;
static constexpr int64_t VD_SIG_OFF       = 0x2A4;

// The 40-byte constant-float block that unambiguously identifies ViewData.
static constexpr const char* VIEW_DATA_SIG =
    "A4 70 7D BF 00 00 00 00 00 00 00 00 00 00 A0 40 "
    "00 00 A0 C0 00 00 00 00 00 00 00 00 CD CC 4C 3F "
    "00 00 00 3F 00 00 80 3E";

struct ViewData {
    uint64_t     base = 0;
    math::Vec3   cam_pos{};
    math::Mat4   view_proj{};
};

// Validate a ViewData candidate: reads matrix, rejects if garbage.
inline bool validate_view_data(HANDLE h, uint64_t vd) {
    math::Mat4 vp{};
    if (!core::rpm(h, vd + VD_VIEW_PROJ_OFF, vp.m, sizeof(vp.m)))
        return false;
    for (int i = 0; i < 16; ++i) {
        float f = vp.m[i];
        if (f != f) return false;                    // NaN
        if (f >  1e9f || f < -1e9f) return false;    // absurd
    }
    return true;
}

// ── Disk cache ────────────────────────────────────────────────────
// File format: two lines of hex.
//   line 1: module base
//   line 2: view-data base
// Located next to the exe as `viewdata.cache`. Persists across runs so
// once we've located ViewData for a given session (module base), the
// next launch reads it back in <1ms.
inline std::string vd_cache_path() {
    char buf[MAX_PATH]{};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string s = buf;
    auto slash = s.find_last_of("\\/");
    if (slash != std::string::npos) s.resize(slash + 1);
    s += "viewdata.cache";
    return s;
}

inline uint64_t vd_cache_read(uint64_t module_base) {
    FILE* f = fopen(vd_cache_path().c_str(), "r");
    if (!f) return 0;
    uint64_t cached_base = 0, cached_vd = 0;
    int rc = fscanf(f, "%llx %llx",
                    (unsigned long long*)&cached_base,
                    (unsigned long long*)&cached_vd);
    fclose(f);
    if (rc != 2) return 0;
    if (cached_base != module_base) return 0;   // stale — different session
    return cached_vd;
}

inline void vd_cache_write(uint64_t module_base, uint64_t vd_base) {
    FILE* f = fopen(vd_cache_path().c_str(), "w");
    if (!f) return;
    fprintf(f, "%llx %llx\n",
            (unsigned long long)module_base,
            (unsigned long long)vd_base);
    fclose(f);
}

// Result of the ViewData search — tells the caller which path we took so
// they can log a helpful message.
enum class ViewDataSource {
    NotFound,
    Cache,   // disk cache from a prior run with the same module base
    Scan,    // pattern scan
};

struct ViewDataResult {
    uint64_t       base   = 0;
    ViewDataSource source = ViewDataSource::NotFound;
};

// Find ViewData:
//   1. Try disk cache (instant, requires same module base as last time)
//   2. Fall through to pattern scan on committed memory
//   3. Cache the discovered base for the next run
inline ViewDataResult find_view_data_cached(HANDLE h, uint64_t module_base) {
    ViewDataResult r{};

    uint64_t cached = vd_cache_read(module_base);
    if (cached && validate_view_data(h, cached)) {
        r.base = cached;
        r.source = ViewDataSource::Cache;
        return r;
    }

    auto hits = core::scan_all(h, 0x10000ULL, 0x7FFFFFFFFFFFULL,
                               VIEW_DATA_SIG, 4);
    for (uint64_t sig_addr : hits) {
        uint64_t vd = sig_addr - VD_SIG_OFF;
        if (validate_view_data(h, vd)) {
            r.base = vd;
            r.source = ViewDataSource::Scan;
            vd_cache_write(module_base, vd);
            return r;
        }
    }
    return r;
}

// Refresh cam pos + matrix from the current ViewData.
inline bool refresh(HANDLE h, ViewData& vd) {
    if (!vd.base) return false;
    if (!core::rpm(h, vd.base + VD_CAM_POS_OFF, &vd.cam_pos, sizeof(vd.cam_pos)))
        return false;
    if (!core::rpm(h, vd.base + VD_VIEW_PROJ_OFF, vd.view_proj.m, sizeof(vd.view_proj.m)))
        return false;
    return true;
}

} // namespace game
