#pragma once
#include "mem.h"
#include <string>
#include <vector>
#include <cstdint>
#include <atomic>
#include <cstdio>
#include <thread>
#include <mutex>

namespace core {

// Global debug flag. Set from main. When on, scanners emit one line per
// N MB scanned (not per region — avoids spam).
inline std::atomic<bool>& scan_debug() {
    static std::atomic<bool> f{false};
    return f;
}
inline void log_scan(const char* fmt, ...) {
    if (!scan_debug().load()) return;
    printf("[Scan] ");
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

struct PatByte { uint8_t v; bool wild; };

inline std::vector<PatByte> parse_pattern(const char* p) {
    std::vector<PatByte> out;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        if (!*p) break;
        if (p[0] == '?') {
            out.push_back({0, true});
            ++p;
            if (*p == '?') ++p;
            continue;
        }
        auto hex = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            return -1;
        };
        int hi = hex(p[0]);
        int lo = hex(p[1]);
        if (hi < 0 || lo < 0) { ++p; continue; }
        out.push_back({(uint8_t)((hi << 4) | lo), false});
        p += 2;
    }
    return out;
}

inline bool match_at(const uint8_t* buf, size_t buf_sz,
                     size_t off, const std::vector<PatByte>& pat)
{
    if (off + pat.size() > buf_sz) return false;
    for (size_t i = 0; i < pat.size(); ++i) {
        if (pat[i].wild) continue;
        if (buf[off + i] != pat[i].v) return false;
    }
    return true;
}

// Scan committed memory in [lo, hi) for `pattern`. Returns absolute addresses.
inline std::vector<uint64_t> scan_all(HANDLE h, uint64_t lo, uint64_t hi,
                                       const char* pattern, size_t limit = 32)
{
    std::vector<uint64_t> hits;
    auto pat = parse_pattern(pattern);
    if (pat.empty()) return hits;

    std::vector<uint8_t> buf;
    for (const auto& r : regions(h, lo, hi)) {
        if (r.RegionSize < pat.size()) continue;
        // Skip huge non-RW regions and image code — ViewData is heap RW.
        if (r.Type == MEM_IMAGE) continue;
        if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            continue;

        buf.resize(r.RegionSize);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, r.BaseAddress, buf.data(),
                               r.RegionSize, &got) || got < pat.size())
            continue;

        for (size_t i = 0; i + pat.size() <= got; ++i) {
            if (match_at(buf.data(), got, i, pat)) {
                hits.push_back((uint64_t)r.BaseAddress + i);
                if (hits.size() >= limit) return hits;
            }
        }
    }
    return hits;
}

// Scan for qword. rw_only=true limits to private RW heap only — this is
// where game objects live and cuts scan time from seconds to milliseconds.
inline std::vector<uint64_t> find_qword(HANDLE h, uint64_t lo, uint64_t hi,
                                        uint64_t target, size_t limit = 64,
                                        bool rw_only = true)
{
    std::vector<uint64_t> hits;
    std::vector<uint8_t> buf;
    uint64_t total_scanned = 0;
    uint64_t next_report   = 128ULL << 20;   // report every 128 MB
    for (const auto& r : regions(h, lo, hi)) {
        if (r.RegionSize < 8) continue;
        if (rw_only) {
            // Private RW heap only — where the body & CC objects live.
            if (r.Type != MEM_PRIVATE) continue;
            if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        } else {
            if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_READONLY | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                continue;
        }
        // Skip huge regions (>256 MB) — those are texture/asset pools, no objects.
        if (r.RegionSize > (256ULL << 20)) continue;

        buf.resize(r.RegionSize);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, r.BaseAddress, buf.data(),
                               r.RegionSize, &got) || got < 8)
            continue;

        total_scanned += got;
        if (total_scanned >= next_report) {
            log_scan("  scanned %llu MB, %zu hits so far",
                     (unsigned long long)(total_scanned >> 20), hits.size());
            next_report += 128ULL << 20;
        }

        const uint64_t* p = (const uint64_t*)buf.data();
        size_t n = got / 8;
        for (size_t i = 0; i < n; ++i) {
            if (p[i] == target) {
                hits.push_back((uint64_t)r.BaseAddress + i * 8);
                if (hits.size() >= limit) return hits;
            }
        }
    }
    return hits;
}

// Batch back-ref scan: single sweep of memory, returns for each target
// the list of addresses whose qword equals it. Much cheaper than calling
// find_qword N times (1 sweep vs N sweeps).
inline std::vector<std::vector<uint64_t>>
find_qword_batch(HANDLE h, uint64_t lo, uint64_t hi,
                 const std::vector<uint64_t>& targets,
                 size_t limit_per_target = 32,
                 bool rw_only = true)
{
    std::vector<std::vector<uint64_t>> out(targets.size());
    if (targets.empty()) return out;

    std::vector<uint8_t> buf;
    uint64_t total_scanned = 0;
    uint64_t next_report   = 128ULL << 20;
    for (const auto& r : regions(h, lo, hi)) {
        if (r.RegionSize < 8) continue;
        if (rw_only) {
            if (r.Type != MEM_PRIVATE) continue;
            if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        } else {
            if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY |
                               PAGE_READONLY | PAGE_EXECUTE_READ |
                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                continue;
        }
        if (r.RegionSize > (256ULL << 20)) continue;

        buf.resize(r.RegionSize);
        SIZE_T got = 0;
        if (!ReadProcessMemory(h, r.BaseAddress, buf.data(),
                               r.RegionSize, &got) || got < 8)
            continue;

        total_scanned += got;
        if (total_scanned >= next_report) {
            log_scan("  batch scan %llu MB", (unsigned long long)(total_scanned >> 20));
            next_report += 128ULL << 20;
        }

        const uint64_t* p = (const uint64_t*)buf.data();
        size_t n = got / 8;
        for (size_t i = 0; i < n; ++i) {
            uint64_t v = p[i];
            for (size_t t = 0; t < targets.size(); ++t) {
                if (v == targets[t]) {
                    if (out[t].size() < limit_per_target) {
                        out[t].push_back((uint64_t)r.BaseAddress + i * 8);
                    }
                    break; // one target per qword
                }
            }
        }
    }
    return out;
}

// Multi-threaded qword scan across a set of already-collected regions.
// Splits regions across N worker threads. Also records which regions
// yielded hits (useful for arena caching — reuse those regions on
// subsequent scans instead of re-enumerating the whole address space).
struct RegionHitInfo {
    uint64_t base = 0;
    uint64_t size = 0;
    size_t   hits = 0;
};

struct QwordScanResult {
    std::vector<uint64_t>       hits;
    std::vector<RegionHitInfo>  hot_regions;   // regions with >=1 hit
    uint64_t                    scanned_bytes = 0;
    uint64_t                    scan_ms       = 0;
};

inline QwordScanResult find_qword_mt(
    HANDLE h,
    const std::vector<MEMORY_BASIC_INFORMATION>& regs,
    uint64_t target,
    size_t limit,
    int workers = 4)
{
    QwordScanResult res{};
    if (workers < 1) workers = 1;
    if (workers > 16) workers = 16;

    auto t0 = std::chrono::steady_clock::now();

    std::atomic<size_t> next_region{0};
    std::mutex mu;
    std::atomic<uint64_t> total{0};

    auto worker = [&]() {
        std::vector<uint8_t> buf;
        for (;;) {
            size_t i = next_region.fetch_add(1);
            if (i >= regs.size()) break;
            const auto& r = regs[i];
            if (r.RegionSize < 8) continue;
            buf.resize(r.RegionSize);
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, r.BaseAddress, buf.data(),
                                   r.RegionSize, &got) || got < 8)
                continue;
            total.fetch_add(got);
            const uint64_t* p = (const uint64_t*)buf.data();
            size_t n = got / 8;
            size_t region_hits = 0;
            std::vector<uint64_t> local_hits;
            for (size_t k = 0; k < n; ++k) {
                if (p[k] == target) {
                    local_hits.push_back((uint64_t)r.BaseAddress + k * 8);
                    ++region_hits;
                }
            }
            if (!local_hits.empty()) {
                std::lock_guard<std::mutex> lk(mu);
                for (uint64_t a : local_hits) {
                    if (res.hits.size() >= limit) break;
                    res.hits.push_back(a);
                }
                res.hot_regions.push_back(
                    { (uint64_t)r.BaseAddress, r.RegionSize, region_hits });
            }
        }
    };

    std::vector<std::thread> ts;
    for (int i = 0; i < workers; ++i) ts.emplace_back(worker);
    for (auto& t : ts) t.join();

    auto t1 = std::chrono::steady_clock::now();
    res.scan_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       t1 - t0).count();
    res.scanned_bytes = total.load();
    return res;
}

// Enumerate committed private RW regions, skipping >256 MB pools.
inline std::vector<MEMORY_BASIC_INFORMATION> scannable_regions(
    HANDLE h, uint64_t lo, uint64_t hi)
{
    std::vector<MEMORY_BASIC_INFORMATION> out;
    for (const auto& r : regions(h, lo, hi)) {
        if (r.RegionSize < 8) continue;
        if (r.Type != MEM_PRIVATE) continue;
        if (!(r.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        if (r.RegionSize > (256ULL << 20)) continue;
        out.push_back(r);
    }
    return out;
}

} // namespace core
