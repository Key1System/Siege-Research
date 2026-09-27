#pragma once
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <thread>
#include <atomic>
#include <chrono>
#include <mutex>
#include <Windows.h>
#include "r6_offsets.h"
#include "r6_math.h"
#include "../driver/driver/driver.hpp"
#include "../debug/debug_log.h"

/*
 * ============================================================================
 *  r6_decrypt.h — R6S pointer/AOB resolution + per-frame state pulls
 * ============================================================================
 *
 *  This build (Y9S5+) doesn't use the legacy TLS-encrypted GameManager
 *  scheme. The chain is:
 *
 *    1. AOB scan .text for GM_AOB_PATTERN  (one-time, then cached)
 *    2. RIP-relative resolve to static slot
 *    3. *static_slot = GameManager
 *    4. *(GameManager + 0x10) = ELC
 *    5. ELC slot[i*0x40 + 0x08] = transform_obj  (ENT2)
 *    6. transform_obj + 0x90 = world position (vec4 with w=1.0)
 *
 *  The view matrix lives on a SEPARATE singleton found by heap AOB.
 *
 *  All driver reads go through `driver::vulnerable.get().read_*()`.
 * ============================================================================
 */

namespace r6::decrypt {

    // ── Convenience aliases ─────────────────────────────────────────────
    template<typename T>
    inline T rpm(uintptr_t addr) {
        return driver::vulnerable.get().read_physical_memory<T>(addr);
    }

    inline bool read_bytes(uintptr_t addr, void* out, size_t n) {
        return driver::vulnerable.get().read_array<uint8_t>(addr, (uint8_t*)out, n);
    }

    // ── Pointer validation ──────────────────────────────────────────────
    inline bool is_valid_ptr(uint64_t ptr) {
        return ptr > offsets::USERMODE_LO && ptr < offsets::USERMODE_HI;
    }

    // ── Pattern parsing helper ──────────────────────────────────────────
    // Converts "48 83 EC 38 ?? ??" into bytes + a same-length mask
    // ('x' = exact match, '?' = wildcard).
    inline void parse_pattern(const char* pat,
                              std::vector<uint8_t>& bytes,
                              std::string& mask) {
        bytes.clear(); mask.clear();
        const char* p = pat;
        while (*p) {
            while (*p == ' ') ++p;
            if (!*p) break;
            if (p[0] == '?') {
                bytes.push_back(0); mask.push_back('?');
                ++p; if (*p == '?') ++p;
            } else {
                char buf[3] = { 0 };
                int n = 0;
                while (n < 2 &&
                       ((*p >= '0' && *p <= '9') ||
                        (*p >= 'a' && *p <= 'f') ||
                        (*p >= 'A' && *p <= 'F'))) {
                    buf[n++] = *p++;
                }
                if (n == 0) { ++p; continue; }
                bytes.push_back((uint8_t)std::strtoul(buf, nullptr, 16));
                mask.push_back('x');
            }
        }
    }

    // ────────────────────────────────────────────────────────────────────
    //  AOB scanner — restricted to the .text section of RainbowSix.exe
    // ────────────────────────────────────────────────────────────────────
    //   - reads PE headers, finds the .text section (or the first
    //     executable section), iterates 1 MB chunks via the driver
    //   - returns absolute address of first match, or 0
    //   - ~13 MB scan range; with a fast driver it takes a few seconds
    //   - cache the result; the offset never changes within a process
    //     lifetime even though ASLR moves the absolute address
    inline uint64_t aob_scan_text(uintptr_t module_base, const char* pat) {
        std::vector<uint8_t> needle;
        std::string mask;
        parse_pattern(pat, needle, mask);
        if (needle.empty()) {
            LOG_ERROR("aob_scan_text: empty pattern after parse");
            return 0;
        }

        // Read DOS + NT headers
        uint8_t hdr[0x400] = {};
        if (!read_bytes(module_base, hdr, sizeof(hdr))) {
            LOG_ERROR("aob_scan_text: header read failed @ 0x%llX", (unsigned long long)module_base);
            return 0;
        }

        // PE-magic sanity check. NullKD's PhysicalReadProcessMemory has
        // been observed to return TRUE with a zero-filled buffer when the
        // CR3 lookup is stale (game restart / page table changed). Bail
        // loudly so we don't silently stay stuck in "GM not found" loops.
        if (hdr[0] != 'M' || hdr[1] != 'Z') {
            LOG_ERROR("aob_scan_text: bad MZ at 0x%llX (got 0x%02X 0x%02X 0x%02X 0x%02X) — driver returned garbage; need to re-attach",
                      (unsigned long long)module_base,
                      hdr[0], hdr[1], hdr[2], hdr[3]);
            return 0;
        }

        uint32_t e_lfanew = *(uint32_t*)(hdr + 0x3C);
        if (e_lfanew + 0x108 > sizeof(hdr)) {
            LOG_ERROR("aob_scan_text: e_lfanew=0x%X out of bounds", e_lfanew);
            return 0;
        }
        if (*(uint32_t*)(hdr + e_lfanew) != 0x4550) {
            LOG_ERROR("aob_scan_text: missing PE signature at e_lfanew=0x%X (got 0x%08X)",
                      e_lfanew, *(uint32_t*)(hdr + e_lfanew));
            return 0;
        }
        uint16_t nSect    = *(uint16_t*)(hdr + e_lfanew + 4 + 2);
        uint16_t sizeOpt  = *(uint16_t*)(hdr + e_lfanew + 4 + 0x10);
        uint32_t sectOff  = e_lfanew + 4 + 20 + sizeOpt;
        if (sectOff + (uint32_t)nSect * 0x28 > sizeof(hdr)) {
            LOG_ERROR("aob_scan_text: section table out of bounds (sectOff=0x%X, nSect=%u)",
                      sectOff, nSect);
            return 0;
        }

        // CRITICAL: NullKD's PhysicalReadProcessMemory walks the requested
        // region page-by-page and FAILS the WHOLE call if any page is
        // unmapped. .text in a 304 MB module has unmapped/guard pages
        // scattered throughout. So a naive 1 MB chunked scan misses huge
        // ranges silently.
        //
        // We do a HYBRID scan:
        //   1. Try a 64 KB chunk (16 pages) — common-case fast path
        //   2. If that fails, fall back to 4 KB (single-page) reads inside
        //      that 64 KB block. Single-page reads are atomic (one
        //      physical translation, one ReadPhysicalAddress) and never
        //      straddle a mapping boundary, so they succeed whenever the
        //      page is mapped at all.
        //   3. The 4 KB reads still have NEEDLE.size() worth of overlap
        //      across their right edge, so a pattern straddling two pages
        //      is found correctly.
        constexpr size_t BIG_CHUNK = 0x10000;  // 64 KB = 16 pages
        constexpr size_t PAGE      = 0x1000;   // 4 KB
        std::vector<uint8_t> bigbuf(BIG_CHUNK + needle.size());
        std::vector<uint8_t> pgbuf (PAGE      + needle.size());

        auto search_buf = [&](const uint8_t* buf, size_t n) -> int64_t {
            if (n < needle.size()) return -1;
            for (size_t k = 0; k + needle.size() <= n; ++k) {
                bool ok = true;
                for (size_t j = 0; j < needle.size(); ++j) {
                    if (mask[j] == 'x' && buf[k + j] != needle[j]) {
                        ok = false; break;
                    }
                }
                if (ok) return (int64_t)k;
            }
            return -1;
        };

        for (uint16_t i = 0; i < nSect; ++i) {
            const uint8_t* s = hdr + sectOff + i * 0x28;
            char name[9] = { 0 };
            memcpy(name, s, 8);
            if (strcmp(name, ".text") != 0) continue;

            uint32_t virt_size = *(uint32_t*)(s + 0x08);
            uint32_t virt_addr = *(uint32_t*)(s + 0x0C);
            if (virt_size == 0) virt_size = *(uint32_t*)(s + 0x10);
            if (!virt_size) continue;

            uint64_t base = (uint64_t)module_base + virt_addr;
            LOG_DEBUG("aob_scan_text: scanning .text @ 0x%llX size 0x%X (hybrid 64K/4K)",
                      base, virt_size);

            size_t big_ok = 0, big_fail = 0, pg_ok = 0, pg_fail = 0;

            for (uint64_t off = 0; off < virt_size; off += BIG_CHUNK) {
                size_t want = (size_t)std::min<uint64_t>(
                    BIG_CHUNK + needle.size(), virt_size - off);
                if (read_bytes(base + off, bigbuf.data(), want)) {
                    ++big_ok;
                    int64_t k = search_buf(bigbuf.data(), want);
                    if (k >= 0) {
                        uint64_t hit = base + off + (uint64_t)k;
                        LOG_INFO("aob_scan_text: hit @ 0x%llX (rva 0x%llX)  "
                                 "[big_ok=%zu big_fail=%zu pg_ok=%zu pg_fail=%zu]",
                                 hit, hit - module_base,
                                 big_ok, big_fail, pg_ok, pg_fail);
                        return hit;
                    }
                    continue;
                }
                ++big_fail;
                // 64 KB read failed → fall back to per-page within this block
                size_t pages_in_block =
                    (size_t)std::min<uint64_t>(BIG_CHUNK, virt_size - off) / PAGE;
                for (size_t pi = 0; pi < pages_in_block; ++pi) {
                    uint64_t pgoff = off + pi * PAGE;
                    size_t pwant = (size_t)std::min<uint64_t>(
                        PAGE + needle.size(), virt_size - pgoff);
                    if (!read_bytes(base + pgoff, pgbuf.data(), pwant)) {
                        ++pg_fail;
                        continue;
                    }
                    ++pg_ok;
                    int64_t k = search_buf(pgbuf.data(), pwant);
                    if (k >= 0) {
                        uint64_t hit = base + pgoff + (uint64_t)k;
                        LOG_INFO("aob_scan_text: hit @ 0x%llX (rva 0x%llX)  "
                                 "[big_ok=%zu big_fail=%zu pg_ok=%zu pg_fail=%zu]",
                                 hit, hit - module_base,
                                 big_ok, big_fail, pg_ok, pg_fail);
                        return hit;
                    }
                }
            }
            LOG_WARN("aob_scan_text: pattern NOT found in .text  "
                     "[big_ok=%zu big_fail=%zu pg_ok=%zu pg_fail=%zu]",
                     big_ok, big_fail, pg_ok, pg_fail);
            return 0;
        }
        LOG_WARN("aob_scan_text: .text section not found in PE headers");
        return 0;
    }

    // ────────────────────────────────────────────────────────────────────
    //  Parallel heap scanner — for the view_translation singleton
    // ────────────────────────────────────────────────────────────────────
    //   Single, aggressive scan path. Replaces the old multi-tier address-
    //   space sweep + .text AOB sigs + .data scan. Live-MCP verification
    //   (see siege/FINDINGS.md §3) confirmed:
    //     * No static pointer to VT exists in RainbowSix.exe .data/.rdata.
    //     * No static pointer to ANY object that holds VT exists either.
    //     * The 7 .text sigs that previously decoded the VT load no longer
    //       match — compiler reorganized that hot path between patches.
    //     * The VT singleton's vtable is referenced ONLY from the singleton
    //       itself anywhere in the entire address space.
    //
    //   So: heap scan is the only path. We make it as fast as possible:
    //
    //   1. Use VirtualQueryEx to enumerate ONLY committed RW regions.
    //      The full address space is ~16 TB but committed memory is ~1-3
    //      GB. Skipping uncommitted ranges is the single biggest win.
    //
    //   2. Spawn N worker threads (= hardware_concurrency, capped at 8).
    //      Each pops a region from a shared queue and scans it via the
    //      driver. The driver's WM_COPYDATA + Notepad pipe is OK with
    //      concurrent senders since each thread has its own request and
    //      output buffer.
    //
    //   3. Read in 16 MB chunks per driver call. NullKD's
    //      VirtualReadProcessMemory copies in one KeStackAttachProcess +
    //      RtlCopyMemory, so big chunks amortize the IPC cost.
    //
    //   4. Pattern: scan for the VT vtable absolute address (8 bytes,
    //      qword-aligned). The vtable lives at offset 0 of the singleton,
    //      so a hit IS the singleton — no back-offset. This is also the
    //      most discriminating pattern (verified live: exactly 1 hit in
    //      the entire process).
    //
    //   5. Progress thread logs %, MB/s, ETA every 500 ms so the user can
    //      see it making progress instead of staring at a frozen log.
    //
    //   With these together first-time discovery is typically ~3-15 s.
    //   After the first run the disk cache makes it instant anyway.
    // ────────────────────────────────────────────────────────────────────
    inline uint64_t parallel_heap_scan_for_singleton(uint64_t needle) {
        // ── 1. Enumerate committed RW regions via VirtualQueryEx ─────────
        DWORD pid = (DWORD)driver::vulnerable.proc_id;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) {
            LOG_ERROR("heap_scan: OpenProcess(PID %u) failed (err %lu)",
                      pid, GetLastError());
            return 0;
        }

        struct region_t { uint64_t base; uint64_t size; };
        std::vector<region_t> regions;
        uint64_t total_bytes = 0;
        {
            constexpr uint64_t HEAP_LO = 0x10000000ULL;
            constexpr uint64_t HEAP_HI = 0x800000000ULL; // 32 GB
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t addr = (uintptr_t)HEAP_LO;
            while (addr < (uintptr_t)HEAP_HI &&
                   VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            {
                if (mbi.RegionSize == 0) break;
                bool committed = (mbi.State == MEM_COMMIT);
                bool writable  = (mbi.Protect & (PAGE_READWRITE
                                               | PAGE_EXECUTE_READWRITE
                                               | PAGE_WRITECOPY
                                               | PAGE_EXECUTE_WRITECOPY)) != 0;
                bool guarded   = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
                if (committed && writable && !guarded) {
                    regions.push_back({(uint64_t)mbi.BaseAddress,
                                       (uint64_t)mbi.RegionSize});
                    total_bytes += mbi.RegionSize;
                }
                addr += mbi.RegionSize;
            }
        }
        CloseHandle(hProc);

        const double total_mb = total_bytes / (1024.0 * 1024.0);
        LOG_INFO("heap_scan: enumerated %zu RW regions, %.1f MB total",
                 regions.size(), total_mb);
        if (regions.empty()) return 0;

        // Sort biggest first so workers that hit big arenas dominate the
        // scan time and progress feels smooth.
        std::sort(regions.begin(), regions.end(),
                  [](const region_t& a, const region_t& b){ return a.size > b.size; });

        // ── 2. Set up shared state for workers ───────────────────────────
        std::atomic<size_t>   next_region{0};
        std::atomic<uint64_t> result{0};
        std::atomic<uint64_t> bytes_done{0};
        std::atomic<size_t>   regions_done{0};
        std::atomic<bool>     stop{false};

        const auto t0 = std::chrono::steady_clock::now();

        // ── 3. Worker: pop region, read in 16 MB chunks, qword-scan ──────
        auto worker = [&](int tid) {
            constexpr size_t CHUNK = 16 * 1024 * 1024; // 16 MB
            std::vector<uint8_t> buf(CHUNK);
            while (!stop.load(std::memory_order_acquire)) {
                size_t idx = next_region.fetch_add(1);
                if (idx >= regions.size()) return;
                const auto& r = regions[idx];

                for (uint64_t off = 0; off < r.size; off += CHUNK) {
                    if (stop.load(std::memory_order_acquire)) return;
                    size_t want = (size_t)std::min<uint64_t>(CHUNK, r.size - off);
                    if (read_bytes(r.base + off, buf.data(), want)) {
                        // qword-aligned scan
                        const size_t end = (want >= 8) ? want - 7 : 0;
                        const uint64_t* p = (const uint64_t*)buf.data();
                        const size_t qcount = end / 8;
                        for (size_t k = 0; k < qcount; ++k) {
                            if (p[k] == needle) {
                                uint64_t hit = r.base + off + k * 8;
                                uint64_t expected = 0;
                                if (result.compare_exchange_strong(expected, hit)) {
                                    LOG_INFO("heap_scan: HIT @ 0x%llX (worker %d, region %zu @ 0x%llX)",
                                             hit, tid, idx, r.base);
                                    stop.store(true, std::memory_order_release);
                                }
                                return;
                            }
                        }
                    }
                    bytes_done.fetch_add(want, std::memory_order_relaxed);
                }
                regions_done.fetch_add(1, std::memory_order_relaxed);
            }
        };

        // ── 4. Progress reporter: every 500 ms ───────────────────────────
        std::thread progress([&]() {
            while (!stop.load(std::memory_order_acquire)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                if (stop.load(std::memory_order_acquire)) break;
                uint64_t done = bytes_done.load(std::memory_order_relaxed);
                size_t   rd   = regions_done.load(std::memory_order_relaxed);
                auto t1 = std::chrono::steady_clock::now();
                double secs = std::chrono::duration<double>(t1 - t0).count();
                if (secs < 0.001) secs = 0.001;
                double done_mb = done / (1024.0 * 1024.0);
                double rate    = done_mb / secs;
                double pct     = total_bytes ? (100.0 * done / total_bytes) : 0.0;
                double eta     = rate > 0.5 ? (total_mb - done_mb) / rate : -1.0;
                if (eta >= 0) {
                    LOG_INFO("heap_scan: %.1f%% (%.0f / %.0f MB) %.1f MB/s, "
                             "regions %zu/%zu, ETA %.1fs",
                             pct, done_mb, total_mb, rate,
                             rd, regions.size(), eta);
                } else {
                    LOG_INFO("heap_scan: %.1f%% (%.0f / %.0f MB) %.1f MB/s, "
                             "regions %zu/%zu",
                             pct, done_mb, total_mb, rate, rd, regions.size());
                }
            }
        });

        // ── 5. Spawn workers ─────────────────────────────────────────────
        unsigned hwc = std::thread::hardware_concurrency();
        if (hwc == 0) hwc = 4;
        const unsigned N = (hwc < 8u) ? hwc : 8u;
        LOG_INFO("heap_scan: spawning %u workers, 16 MB chunks", N);

        std::vector<std::thread> workers;
        workers.reserve(N);
        for (unsigned i = 0; i < N; ++i)
            workers.emplace_back(worker, (int)i);

        for (auto& t : workers) t.join();
        stop.store(true, std::memory_order_release);
        progress.join();

        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();
        uint64_t hit = result.load();
        if (hit) {
            LOG_INFO("heap_scan: done in %.2fs (scanned %.1f MB, %.1f MB/s avg)",
                     secs, bytes_done.load() / (1024.0 * 1024.0),
                     bytes_done.load() / (1024.0 * 1024.0) / (secs > 0.001 ? secs : 1.0));
        } else {
            LOG_WARN("heap_scan: NO HIT — scanned %.1f MB across %zu regions in %.2fs",
                     bytes_done.load() / (1024.0 * 1024.0), regions.size(), secs);
        }
        return hit;
    }

    // ────────────────────────────────────────────────────────────────────
    //  parallel_heap_scan_all_singletons — collect EVERY match
    // ────────────────────────────────────────────────────────────────────
    //
    //  R6 has multiple objects sharing the view-translation vtable (one
    //  per camera type — main player POV, ADS scope, spectator,
    //  cinematic, …). Stopping at the first hit can land us on the
    //  wrong one, which is what caused the "ESP only works while
    //  scoped in" bug. This variant keeps scanning until either:
    //    * `max_results` matches collected, OR
    //    * the heap is fully walked.
    //
    //  Returns matches in scan order. Caller picks the active one by
    //  live-sampling the camera/VP fields.
    inline std::vector<uint64_t> parallel_heap_scan_all_singletons(
        uint64_t needle, size_t max_results = 16)
    {
        std::vector<uint64_t> out;

        DWORD pid = (DWORD)driver::vulnerable.proc_id;
        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProc) {
            LOG_ERROR("heap_scan_all: OpenProcess(PID %u) failed (err %lu)",
                      pid, GetLastError());
            return out;
        }

        struct region_t { uint64_t base; uint64_t size; };
        std::vector<region_t> regions;
        uint64_t total_bytes = 0;
        {
            constexpr uint64_t HEAP_LO = 0x10000000ULL;
            constexpr uint64_t HEAP_HI = 0x800000000ULL;
            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t addr = (uintptr_t)HEAP_LO;
            while (addr < (uintptr_t)HEAP_HI &&
                   VirtualQueryEx(hProc, (LPCVOID)addr, &mbi, sizeof(mbi)))
            {
                if (mbi.RegionSize == 0) break;
                bool committed = (mbi.State == MEM_COMMIT);
                bool writable  = (mbi.Protect & (PAGE_READWRITE
                                               | PAGE_EXECUTE_READWRITE
                                               | PAGE_WRITECOPY
                                               | PAGE_EXECUTE_WRITECOPY)) != 0;
                bool guarded   = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
                if (committed && writable && !guarded) {
                    regions.push_back({(uint64_t)mbi.BaseAddress,
                                       (uint64_t)mbi.RegionSize});
                    total_bytes += mbi.RegionSize;
                }
                addr += mbi.RegionSize;
            }
        }
        CloseHandle(hProc);
        if (regions.empty()) return out;
        std::sort(regions.begin(), regions.end(),
                  [](const region_t& a, const region_t& b){ return a.size > b.size; });

        std::mutex            results_mu;
        std::atomic<size_t>   next_region{0};
        std::atomic<bool>     stop{false};

        auto worker = [&]() {
            constexpr size_t CHUNK = 16 * 1024 * 1024;
            std::vector<uint8_t> buf(CHUNK);
            while (!stop.load(std::memory_order_acquire)) {
                size_t idx = next_region.fetch_add(1);
                if (idx >= regions.size()) return;
                const auto& r = regions[idx];
                for (uint64_t off = 0; off < r.size; off += CHUNK) {
                    if (stop.load(std::memory_order_acquire)) return;
                    size_t want = (size_t)std::min<uint64_t>(CHUNK, r.size - off);
                    if (!read_bytes(r.base + off, buf.data(), want)) continue;
                    const size_t end = (want >= 8) ? want - 7 : 0;
                    const uint64_t* p = (const uint64_t*)buf.data();
                    const size_t qcount = end / 8;
                    for (size_t k = 0; k < qcount; ++k) {
                        if (p[k] != needle) continue;
                        uint64_t hit = r.base + off + k * 8;
                        std::lock_guard<std::mutex> lk(results_mu);
                        out.push_back(hit);
                        if (out.size() >= max_results) {
                            stop.store(true, std::memory_order_release);
                            return;
                        }
                    }
                }
            }
        };

        unsigned hwc = std::thread::hardware_concurrency();
        if (hwc == 0) hwc = 4;
        const unsigned N = (hwc < 8u) ? hwc : 8u;

        std::vector<std::thread> workers;
        workers.reserve(N);
        for (unsigned i = 0; i < N; ++i) workers.emplace_back(worker);
        for (auto& t : workers) t.join();

        // De-dup (workers can race on the same hit if regions overlap).
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());

        LOG_INFO("heap_scan_all: %zu candidate(s) for vtable 0x%llX",
                 out.size(), (unsigned long long)needle);
        return out;
    }

    // ────────────────────────────────────────────────────────────────────
    //  Roster window scan — find every ENT1 within ±WINDOW bytes of a
    //  confirmed-player ENT1 by searching for qwords equal to the seed's
    //  vtable.
    // ────────────────────────────────────────────────────────────────────
    //
    //  Premise: R6 allocates the per-match player entities from a small
    //  set of arenas, so the 10 (or however many) player ENT1s land in a
    //  fairly tight heap span — usually well under ±1 MB.
    //
    //  Once we have ONE confirmed-player ENT1 (e.g. the local pawn, found
    //  via the existing classify_ent1 in the ELC walk), we:
    //    1. Read its vtable (8 bytes at offset 0).
    //    2. Scan ±WINDOW bytes around it for any qword equal to that
    //       vtable. Qword-aligned reads only — every ENT1 in this build
    //       is 8-byte aligned.
    //    3. Each hit IS an ENT1 address (vtable lives at offset 0).
    //
    //  The chunked read handles unmapped pages by falling back to per-page
    //  reads — same hybrid logic as aob_scan_text.
    //
    //  Returns ALL hits in arbitrary order. Caller can sort / dedupe.
    inline std::vector<uint64_t> scan_roster_window(uint64_t seed_ent1,
                                                    uint64_t vtable_abs,
                                                    int64_t  window_bytes = 0x100000) // ±1 MB
    {
        std::vector<uint64_t> out;
        if (!is_valid_ptr(seed_ent1) || vtable_abs == 0) return out;

        // Clamp to user-mode lower bound so we don't underflow on tiny heaps.
        uint64_t lo = (seed_ent1 > (uint64_t)window_bytes + offsets::USERMODE_LO)
                          ? seed_ent1 - (uint64_t)window_bytes
                          : offsets::USERMODE_LO;
        uint64_t hi = seed_ent1 + (uint64_t)window_bytes;

        // Align lo to 8 so all reads stay qword-aligned (ENT1 alignment).
        lo = (lo + 7) & ~7ULL;

        constexpr size_t BIG = 0x10000; // 64 KB
        constexpr size_t PAGE = 0x1000;
        std::vector<uint8_t> bigbuf(BIG);
        std::vector<uint8_t> pgbuf (PAGE);

        auto scan_qwords = [&](const uint8_t* buf, size_t n, uint64_t base_addr) {
            // n already a multiple of 8 after the alignment we use below.
            const uint64_t* q = (const uint64_t*)buf;
            size_t qc = n / 8;
            for (size_t i = 0; i < qc; ++i) {
                if (q[i] == vtable_abs) {
                    out.push_back(base_addr + i * 8);
                }
            }
        };

        for (uint64_t off = lo; off < hi; off += BIG) {
            size_t want = (size_t)std::min<uint64_t>(BIG, hi - off);
            want &= ~(size_t)7; // keep aligned
            if (want == 0) break;
            if (read_bytes(off, bigbuf.data(), want)) {
                scan_qwords(bigbuf.data(), want, off);
                continue;
            }
            // 64 KB read failed — page-by-page fallback.
            for (size_t pi = 0; pi < want; pi += PAGE) {
                size_t pw = (size_t)std::min<uint64_t>(PAGE, hi - (off + pi));
                pw &= ~(size_t)7;
                if (pw == 0) break;
                if (!read_bytes(off + pi, pgbuf.data(), pw)) continue;
                scan_qwords(pgbuf.data(), pw, off + pi);
            }
        }

        // Dedupe (shouldn't be needed since reads don't overlap, but cheap).
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        LOG_INFO("roster_scan: %zu hit(s) for vtable 0x%llX in [0x%llX, 0x%llX]",
                 out.size(), (unsigned long long)vtable_abs,
                 (unsigned long long)lo, (unsigned long long)hi);
        return out;
    }

    // ── Cached resolution state ────────────────────────────────────────
    // One copy per process. Reset when the module base changes (game
    // restart).
    // After this many consecutive null/junk reads from the cached GM
    // slot, assume the cache is stale (game patched, RVA shifted) and
    // re-run the AOB scan. 30 × 2s = 60s of menu time is normal —
    // bump higher than that so we don't thrash during a long lobby wait.
    inline constexpr int GM_STALE_THRESHOLD = 60;

    struct cached_keys_t {
        uintptr_t module_base       = 0;
        uint64_t  gm_static_slot    = 0;  // RIP-resolved address of the qword holding GM
        int       gm_null_streak    = 0;  // consecutive null reads from the slot
        uint64_t  view_translation  = 0;  // currently-active VT singleton base
        std::vector<uint64_t> vt_candidates;  // every heap object with the VT vtable
        size_t    vt_index          = 0;  // which candidate is selected
        int       counter           = 0;

        // ── Roster cache ────────────────────────────────────────────────
        // Hot list of ENT1 pointers found by scanning ±1 MB around a
        // confirmed-player ENT1. Read positions directly from these every
        // frame; skip the ELC walk + classify_ent1 entirely.
        std::vector<uint64_t> roster;       // ENT1 addresses
        uint64_t  roster_seed       = 0;    // the ENT1 we scanned around
        uint64_t  roster_vtable     = 0;    // absolute vtable address used as the needle
        uint64_t  roster_window_lo  = 0;    // scan window bounds (for cheap "is in window")
        uint64_t  roster_window_hi  = 0;

        bool needs_refresh() const { return false; }
        void invalidate() {
            gm_static_slot = 0;
            gm_null_streak = 0;
            view_translation = 0;
            vt_candidates.clear();
            vt_index = 0;
            roster.clear();
            roster_seed = 0;
            roster_vtable = 0;
            roster_window_lo = roster_window_hi = 0;
        }
    };

    // Pawn-list-shaped result so the existing reader_loop keeps compiling.
    // In the new chain, "array_ptr" is the ELC base and "count" is the
    // walked-through count (since ELC has no reliable count field, we
    // cap at ELC_MAX_SLOTS and stop on consecutive nulls).
    struct pawn_list_t {
        uint64_t array_ptr = 0;
        uint64_t count     = 0;

        bool is_valid() const {
            return array_ptr > offsets::USERMODE_LO &&
                   array_ptr < offsets::USERMODE_HI;
        }
    };

    // ── Persistent GM static-slot cache (skips AOB scan on subsequent runs) ──
    //
    // The static slot's RVA in RainbowSix.exe stays stable across game restarts
    // as long as Ubi doesn't relink. We cache the RVA — NOT the absolute — so
    // ASLR rebase still works. On load we just do `module_base + rva` and
    // re-verify the slot reads a sane pointer (or null when in menu).
    struct gm_cache_t {
        uint64_t magic;       // 'SRSGMS' = valid
        uint64_t static_rva;  // [module_base + static_rva] = GM*
        uint64_t last_addr;   // last session's absolute slot (debug/fallback)
    };
    inline constexpr uint64_t GM_CACHE_MAGIC = 0x534D4736525353ULL;  // 'SSR6GMS'

    inline std::string gm_cache_path() {
        char buf[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return std::string();
        std::string p = buf;
        p += "\\SlopedR6";
        CreateDirectoryA(p.c_str(), nullptr);
        p += "\\gm.cache";
        return p;
    }
    inline bool load_cached_gm(gm_cache_t& out) {
        auto p = gm_cache_path();
        if (p.empty()) return false;
        HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        BOOL ok = ReadFile(f, &out, sizeof(out), &got, nullptr);
        CloseHandle(f);
        return ok && got == sizeof(out) && out.magic == GM_CACHE_MAGIC;
    }
    inline void save_cached_gm(uint64_t static_rva, uint64_t last_addr) {
        auto p = gm_cache_path();
        if (p.empty()) return;
        HANDLE f = CreateFileA(p.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return;
        gm_cache_t c{ GM_CACHE_MAGIC, static_rva, last_addr };
        DWORD wrote = 0;
        WriteFile(f, &c, sizeof(c), &wrote, nullptr);
        CloseHandle(f);
    }

    // ────────────────────────────────────────────────────────────────────
    //  resolve_gm_static_slot — disk cache → AOB scan fallback
    // ────────────────────────────────────────────────────────────────────
    //   Two paths:
    //     (a) Disk cache  — read cached RVA, verify slot is in module
    //                       range. If valid, skip the scan entirely.
    //     (b) AOB scan    — scans .text for GM_AOB_PATTERN, RIP-resolves
    //                       the disp32. Persists RVA to disk on success.
    //
    //   Returns true on success. Cached value lives in keys.gm_static_slot.
    inline bool resolve_gm_static_slot(uintptr_t module_base, cached_keys_t& keys) {
        if (keys.gm_static_slot && keys.module_base == module_base) return true;
        keys.module_base = module_base;

        auto validate_slot = [&](uint64_t slot) -> bool {
            // Slot itself must live inside the module's read-only data area.
            return slot >= module_base && slot < module_base + 0x20000000ULL;
        };

        // 1) Try disk cache first — instant if the RVA is still good.
        gm_cache_t cache{};
        if (load_cached_gm(cache) && cache.static_rva) {
            uint64_t slot = (uint64_t)module_base + cache.static_rva;
            if (validate_slot(slot)) {
                keys.gm_static_slot = slot;
                LOG_INFO("GM INSTANT from disk cache: 0x%llX (rva 0x%llX)",
                         slot, cache.static_rva);
                return true;
            }
        }

        // 2) AOB scan fallback. Cache the RVA on success.
        uint64_t hit = aob_scan_text(module_base, offsets::GM_AOB_PATTERN);
        if (!hit) return false;
        int32_t rel = rpm<int32_t>(hit + offsets::GM_DISP_OFF);
        keys.gm_static_slot = (uint64_t)((int64_t)(hit + offsets::GM_RIP_OFF) + (int64_t)rel);
        uint64_t rva = keys.gm_static_slot - module_base;
        LOG_INFO("GM static slot resolved: 0x%llX (rva 0x%llX)",
                 keys.gm_static_slot, rva);
        save_cached_gm(rva, keys.gm_static_slot);
        return true;
    }

    // ── GameManager fetch ───────────────────────────────────────────────
    inline uint64_t read_game_manager(uintptr_t module_base) {
        // Backwards-compat path: callers without a `keys` ref scan once
        // and don't cache. The reader thread should use the cached path.
        cached_keys_t scratch;
        if (!resolve_gm_static_slot(module_base, scratch)) return 0;
        uint64_t gm = rpm<uint64_t>(scratch.gm_static_slot);
        if (!is_valid_ptr(gm)) return 0;
        // Sanity: vtable must live inside the module
        uint64_t vt = rpm<uint64_t>(gm);
        if (vt < module_base || vt > module_base + 0x20000000ULL) return 0;
        return gm;
    }

    inline uint64_t read_game_manager_cached(uintptr_t module_base, cached_keys_t& keys) {
        if (!resolve_gm_static_slot(module_base, keys)) return 0;
        uint64_t gm = rpm<uint64_t>(keys.gm_static_slot);
        // The static slot may legitimately be 0 in menu/lobby OR may be
        // junk because the cached RVA is stale (game patched, slot moved).
        // Distinguish: count consecutive null reads — past a threshold
        // assume the cache is stale and force a re-scan. The AOB scan
        // overwrites keys.gm_static_slot and persists the fresh RVA.
        if (!is_valid_ptr(gm)) {
            if (++keys.gm_null_streak >= GM_STALE_THRESHOLD) {
                keys.gm_null_streak = 0;
                keys.gm_static_slot = 0;  // force AOB re-scan next call
                LOG_INFO("GM slot returned null %d× — re-scanning AOB (cache may be stale)",
                         GM_STALE_THRESHOLD);
            }
            return 0;
        }
        uint64_t vt = rpm<uint64_t>(gm);
        if (vt < module_base || vt > module_base + 0x20000000ULL) {
            // Got something non-null but vtable isn't in module — definitely
            // junk from a stale slot. Force re-scan immediately.
            keys.gm_null_streak = 0;
            keys.gm_static_slot = 0;
            LOG_INFO("GM vtable not in module (junk slot 0x%llX) — re-scanning AOB",
                     keys.gm_static_slot);
            return 0;
        }
        keys.gm_null_streak = 0;  // success
        return gm;
    }

    // Legacy wrapper for callers that still pass tls_slot
    inline uint64_t decrypt_game_manager(uintptr_t base, uint64_t /*tls_slot*/) {
        return read_game_manager(base);
    }

    // ── Refresh cached resolution state ─────────────────────────────────
    inline bool refresh_keys(uintptr_t base, uint64_t /*tls*/, cached_keys_t& k) {
        k.counter = 0;
        return resolve_gm_static_slot(base, k);
    }
    inline bool refresh_frame_keys(cached_keys_t& /*k*/) { return true; }

    // ────────────────────────────────────────────────────────────────────
    //  GameManager structural probe — used to find non-render-culled
    //  pointer chains (player roster / network actor list / etc.) when
    //  the default `GM + 0x10` ELC turns out to be render-managed.
    // ────────────────────────────────────────────────────────────────────
    //
    //  Reads the first 0x200 bytes of GameManager and classifies every
    //  qword:
    //    * in-module    → likely a vtable (printed as RVA)
    //    * heap pointer → followed one level: reads 0x40 bytes at the
    //                     target, prints first qword (likely *its*
    //                     vtable if it's an object) and any nearby
    //                     count-sized small ints / pointer-sized
    //                     fields. This is the tell for "array of
    //                     pointers to objects with a player class".
    //    * small int    → noted as a possible count/capacity field
    //    * other        → skipped
    //
    //  Output goes to the debug log with offsets so the human reading
    //  it can spot:
    //    "GM+0x18 -> heap 0x... -> *=<player vtable RVA>"
    //  → that GM+0x18 might be an array of player pawns.
    inline bool probe_in_module(uint64_t v, uintptr_t module_base) {
        return v >= module_base && v < module_base + 0x20000000ULL;
    }

    // Dereference one level: read 0x40 bytes at addr and report shape.
    // The point is to spot "array of player-class pointers" patterns.
    inline void probe_follow_one(uint64_t addr, uintptr_t module_base,
                                 uint64_t parent_off)
    {
        if (!is_valid_ptr(addr)) return;
        uint8_t buf[0x40] = {};
        if (!read_bytes(addr, buf, sizeof(buf))) {
            LOG_INFO("    +0x%03llX -> 0x%llX  [unreadable]",
                     (unsigned long long)parent_off, (unsigned long long)addr);
            return;
        }

        uint64_t v0 = *(uint64_t*)(buf + 0x00);
        bool v0_mod = probe_in_module(v0, module_base);

        // Inspect a few offsets that often carry "count" or "pointer"
        // semantics in array-shaped structs.
        char tail[256] = {};
        size_t pos = 0;
        for (size_t off = 0x08; off < 0x40 && pos < sizeof(tail) - 32; off += 8) {
            uint64_t v = *(uint64_t*)(buf + off);
            if (v == 0) continue;
            if (v > 0 && v < 4096) {
                int n = snprintf(tail + pos, sizeof(tail) - pos,
                                 "  +%02zX=%llu", off, (unsigned long long)v);
                if (n > 0) pos += (size_t)n;
            } else if (is_valid_ptr(v)) {
                // Could be an inner array pointer. Dereference once more
                // (cheap: 8 bytes) and see if it's class-shaped.
                uint64_t inner = rpm<uint64_t>(v);
                bool inner_mod = probe_in_module(inner, module_base);
                int n = snprintf(tail + pos, sizeof(tail) - pos,
                                 "  +%02zX=ptr->0x%llX%s", off,
                                 (unsigned long long)v,
                                 inner_mod ? "[class]" : "");
                if (n > 0) pos += (size_t)n;
            }
        }

        if (v0_mod) {
            uint64_t rva = v0 - module_base;
            LOG_INFO("    +0x%03llX -> 0x%llX  *=class@RVA 0x%llX%s",
                     (unsigned long long)parent_off,
                     (unsigned long long)addr,
                     (unsigned long long)rva,
                     tail);
        } else {
            LOG_INFO("    +0x%03llX -> 0x%llX  *=0x%llX%s",
                     (unsigned long long)parent_off,
                     (unsigned long long)addr,
                     (unsigned long long)v0,
                     tail);
        }
    }

    inline void probe_game_manager(uint64_t gm, uintptr_t module_base) {
        if (!is_valid_ptr(gm)) return;

        constexpr size_t SCAN = 0x200;
        uint8_t buf[SCAN] = {};
        if (!read_bytes(gm, buf, SCAN)) {
            LOG_WARN("probe_game_manager: read failed @ 0x%llX",
                     (unsigned long long)gm);
            return;
        }

        LOG_INFO("=== GameManager probe @ 0x%llX (0x%zX bytes) ===",
                 (unsigned long long)gm, SCAN);

        // First pass: log every offset's classification.
        std::vector<std::pair<uint64_t, uint64_t>> follow_list;
        for (size_t off = 0; off < SCAN; off += 8) {
            uint64_t v = *(uint64_t*)(buf + off);
            if (v == 0) continue;
            if (probe_in_module(v, module_base)) {
                LOG_INFO("  GM+0x%03zX  0x%016llX  [module RVA 0x%llX]",
                         off, (unsigned long long)v,
                         (unsigned long long)(v - module_base));
            } else if (is_valid_ptr(v)) {
                LOG_INFO("  GM+0x%03zX  0x%016llX  [heap ptr]",
                         off, (unsigned long long)v);
                follow_list.push_back({off, v});
            } else if (v > 0 && v < 1000000) {
                int32_t lo = (int32_t)(v & 0xFFFFFFFF);
                int32_t hi = (int32_t)(v >> 32);
                LOG_INFO("  GM+0x%03zX  0x%016llX  [int? lo=%d hi=%d]",
                         off, (unsigned long long)v, lo, hi);
            }
        }

        // Second pass: follow each heap pointer one level deep so we
        // can spot "ptr -> object whose vtable is in the player set"
        // patterns. That's the signature of the right container.
        if (!follow_list.empty()) {
            LOG_INFO("--- Follow heap pointers (one level) ---");
            for (const auto& kv : follow_list) {
                probe_follow_one(kv.second, module_base, kv.first);
            }
        }

        LOG_INFO("=== GameManager probe end ===");
    }

    // ── ELC walk ────────────────────────────────────────────────────────
    //  In the new chain, this returns the ELC base address; the count
    //  is filled by the caller as it walks.
    inline pawn_list_t read_pawn_list(uint64_t gm) {
        pawn_list_t pl{};
        pl.array_ptr = rpm<uint64_t>(gm + offsets::GM_ELC_PTR);
        pl.count     = offsets::ELC_MAX_SLOTS;
        return pl;
    }

    // Legacy wrapper
    inline pawn_list_t decrypt_pawn_list(uint64_t gm, const cached_keys_t& /*k*/) {
        return read_pawn_list(gm);
    }

    // ── ELC slot read ───────────────────────────────────────────────────
    // Reads a single slot's ENT2 (= transform_obj). Returns 0 if the slot
    // is empty / pointer is bogus.
    inline uint64_t read_elc_ent2(uint64_t elc, int slot_index) {
        uint64_t slot = elc + (uint64_t)slot_index * offsets::ELC_STRIDE;
        uint64_t ent2 = rpm<uint64_t>(slot + offsets::ELC_ENT2);
        return is_valid_ptr(ent2) ? ent2 : 0;
    }

    inline uint64_t read_elc_ent1(uint64_t elc, int slot_index) {
        uint64_t slot = elc + (uint64_t)slot_index * offsets::ELC_STRIDE;
        uint64_t ent1 = rpm<uint64_t>(slot + offsets::ELC_ENT1);
        return is_valid_ptr(ent1) ? ent1 : 0;
    }

    // ── Single entity read (no decryption needed in this build) ─────────
    inline uint64_t read_entity(uint64_t entity_ptr) {
        return is_valid_ptr(entity_ptr) ? entity_ptr : 0;
    }

    // ────────────────────────────────────────────────────────────────────
    //  Player detection — vtable allowlist + status bitfield
    // ────────────────────────────────────────────────────────────────────
    //   The reference cheat's pure-ID approach (id < 1000) was for an
    //   older R6 build; in Y9S5 player IDs sit in the [2000, 2100] range
    //   (verified live, FINDINGS §12) so it filters out every player.
    //
    //   The robust filter here is two cheap reads:
    //     1. *(ENT1+0x00) = class vtable. Must match one of the known
    //        player vtables (PLAYER_VT_RVAS in offsets.h).
    //     2. *(ENT1+0xB0) = status bitfield. Sub-classifies the survivor
    //        into VALID / TEAM / LOCAL / DEAD via byte3 + byte4.
    //
    //   Vtable RVAs are stable across patches but if Ubi adds a new pawn
    //   class (or recompiles), they shift — easy fix is to drop a fresh
    //   RVA into PLAYER_VT_RVAS. The bitfield encoding has been the same
    //   shape for several years.
    enum class ent_role_t {
        NOT_PLAYER = 0,  // class vtable not in allowlist
        DEAD       = 1,  // corpse / disconnected
        VALID      = 2,  // alive enemy
        TEAM       = 3,  // squadmate
        LOCAL      = 4,  // you
    };

    // Cache: ENT1 -> known vtable RVA. Keyed by ENT1 heap pointer.
    // Vtables don't change for a live entity; caching saves one driver
    // round-trip per known entity per scan.
    //
    // Entries above ~10000 get reset on next scan to avoid unbounded
    // growth across matches.
    inline std::unordered_map<uint64_t, uint64_t>& vtable_cache() {
        static std::unordered_map<uint64_t, uint64_t> c;
        return c;
    }
    // Forward decl so clear_vtable_cache can reach the runtime map below.
    inline std::unordered_map<uint64_t, int>& runtime_player_vts();

    inline void clear_vtable_cache() {
        vtable_cache().clear();
        // Module base may shift on re-attach, invalidating recorded
        // RVAs in the auto-discovery allowlist — wipe it too.
        runtime_player_vts().clear();
    }

    // ── Runtime player-vtable allowlist (auto-discovery) ────────────────
    //
    // Hardcoded PLAYER_VT_RVAS only covers 4 known operator/proxy
    // classes; R6 has more (e.g. spectator-state proxies, replicated
    // pawn variants). Any pawn whose vtable isn't in the static list
    // gets dropped — that's why "some entities never show up at all"
    // could happen.
    //
    // This map is populated when a candidate ENT1 looks player-shaped
    // (role-ID in [1,999] AND status bitfield has a known shape AND
    // ENT2 produced a valid in-bounds position). After it accumulates
    // a couple of votes for the same vtable, we treat that vtable as a
    // player class for the rest of the session. New discoveries are
    // logged so they can be folded into PLAYER_VT_RVAS later.
    //
    // Cleared whenever the cheat re-attaches (clear_vtable_cache).
    inline std::unordered_map<uint64_t, int>& runtime_player_vts() {
        static std::unordered_map<uint64_t, int> m;
        return m;
    }
    inline constexpr int RUNTIME_VT_VOTES_REQUIRED = 2;

    // Classification using the bitfield AFTER vtable acceptance.
    // Pulled out so both the hardcoded path and the auto-discovery path
    // can share it.
    inline ent_role_t status_to_role(uint64_t bf) {
        if (bf == 0) return ent_role_t::VALID;
        uint8_t b3 = (uint8_t)((bf >> 24) & 0xFF);
        uint8_t b4 = (uint8_t)((bf >> 32) & 0xFF);
        if (b3 == 0xFA) return ent_role_t::DEAD;
        if (b4 == 0x80) return ent_role_t::DEAD;
        if (b4 == 0x02) return ent_role_t::TEAM;
        if (b4 == 0x00) return ent_role_t::LOCAL;
        return ent_role_t::VALID;
    }

    // "Plausible status bitfield" — used during auto-discovery to avoid
    // accepting completely random heap qwords as player status. The
    // values that WE care about (TEAM/LOCAL/DEAD/VALID) all fall on
    // specific byte values, so we can vet candidates the same way.
    inline bool plausible_status_bf(uint64_t bf) {
        if (bf == 0) return true;                        // lobby state
        uint8_t b3 = (uint8_t)((bf >> 24) & 0xFF);
        uint8_t b4 = (uint8_t)((bf >> 32) & 0xFF);
        if (b3 == 0xFA) return true;
        if (b4 == 0x80 || b4 == 0x02 || b4 == 0x00 || b4 == 0x01) return true;
        // Otherwise this looks like a non-player object — random bits
        // in those bytes are very unlikely to land on the known shapes.
        return false;
    }

    // ── Post-update build classifier ─────────────────────────────────────
    //
    // Status-byte heuristics (the old `byte3==0xFA`, `byte4==0x02` etc.)
    // read zero on every player in the post-update build, so they cannot
    // tell DEAD/TEAM/LOCAL apart anymore. Until we re-map those fields
    // we use the strictest reliable filter we have, which is sufficient
    // to draw boxes on real players only:
    //
    //   1. Vtable must be PLAYER_VT_RVAS[0] (operator avatar). The other
    //      three RVAs in PLAYER_VT_RVAS are either embedded sub-records
    //      of an operator avatar (sub-object at +0x280 → fake ELC slot)
    //      or system fillers (LocalPlayer-wrapper bot slot, sentinel).
    //   2. ENT1 must not be the bot/empty-slot LocalPlayer filler — we
    //      detect those by checking ENT1+0x0C is a hash-shaped UID
    //      (non-zero, not bit-patterned).
    //
    // Returns VALID for every accepted player. We don't classify into
    // TEAM/LOCAL/DEAD yet (status bytes still need re-mapping); the
    // game_reader's is_local heuristic (distance<1 m from camera)
    // handles local-player tagging.
    inline ent_role_t classify_ent1(uint64_t ent1, uintptr_t module_base) {
        if (!is_valid_ptr(ent1)) return ent_role_t::NOT_PLAYER;

        // Vtable read with cache (cleared on re-attach).
        auto& cache = vtable_cache();
        uint64_t rva;
        auto cit = cache.find(ent1);
        if (cit != cache.end()) {
            rva = cit->second;
        } else {
            uint64_t vt = rpm<uint64_t>(ent1);
            if (vt < module_base || vt >= module_base + 0x20000000ULL) {
                cache[ent1] = (uint64_t)-1;
                return ent_role_t::NOT_PLAYER;
            }
            rva = vt - module_base;
            cache[ent1] = rva;
        }
        if (rva == (uint64_t)-1) return ent_role_t::NOT_PLAYER;

        // PLAYER_VT_RVAS[0] is the only "real" player class. Everything
        // else (network slot, LocalPlayer wrapper, legacy) is either a
        // duplicate alias of an operator avatar or a system filler.
        if (rva != offsets::PLAYER_VT_RVAS[0]) {
            return ent_role_t::NOT_PLAYER;
        }

        // UID sanity: real players have a hash-shaped value (non-zero,
        // non-trivial). The LocalPlayer-wrapper bot filler we observed
        // had things like 0x49249200 (bit-patterned). Reject UIDs that
        // are 0 or have the obvious bot-filler bit-pattern.
        uint32_t uid = rpm<uint32_t>(ent1 + offsets::ENT1_UID_HI32);
        if (uid == 0) return ent_role_t::NOT_PLAYER;
        // Cheap "looks bit-patterned" check: too few bits set or too many
        // matching nibbles. The bot filler we saw had nibble pattern
        // 4-9-2-4-9-2-0-0; a real-world hash never hits that.
        {
            uint32_t nibble0 = (uid >>  0) & 0xF;
            uint32_t nibble1 = (uid >>  4) & 0xF;
            uint32_t nibble2 = (uid >>  8) & 0xF;
            uint32_t nibble3 = (uid >> 12) & 0xF;
            uint32_t nibble4 = (uid >> 16) & 0xF;
            uint32_t nibble5 = (uid >> 20) & 0xF;
            // Reject obvious 4924 9200 / 9249 0049 style repeated
            // patterns where multiple low nibbles are 0 or 9.
            if ((nibble0 == 0 && nibble1 == 0) &&
                (nibble2 == 2) && (nibble4 == 9)) {
                return ent_role_t::NOT_PLAYER;
            }
        }

        return ent_role_t::VALID;
    }

    // Legacy wrapper
    inline uint64_t decrypt_entity(uint64_t pawn, const cached_keys_t& /*k*/) {
        return read_entity(pawn);
    }

    // ── Read entity world position from a transform_obj (ENT2) ──────────
    //
    // Position is at +0x90 as a vec4 (X, Y, Z, w). Active player pawns
    // have w == 1.0 exactly. BUT R6 lazily ticks transforms for entities
    // outside the engine's active processing bubble — w can be 0, NaN,
    // or stale until the entity is "live" again. Strictly rejecting on
    // w!=1 caused the "stand far → box vanishes, walk closer → box
    // appears" behavior even though the entity was in the ELC the whole
    // time. The new policy:
    //
    //   * Reject only on numerical garbage (NaN/Inf / out-of-bounds).
    //   * Trust X,Y,Z values that lie in the playable-world range.
    //
    // For genuine non-transform component pointers, the X/Y/Z bytes
    // almost always overflow the 50000-unit bound or are NaN, so they
    // still get filtered.
    inline vector3_t read_entity_position(uint64_t ent2) {
        vector3_t out{};
        if (!is_valid_ptr(ent2)) return out;
        float v[4] = {};
        if (!read_bytes(ent2 + offsets::T_POSITION, v, sizeof(v))) return out;
        if (!std::isfinite(v[0]) || !std::isfinite(v[1]) || !std::isfinite(v[2]))
            return {};
        if (fabsf(v[0]) > 50000.f || fabsf(v[1]) > 50000.f || fabsf(v[2]) > 50000.f)
            return {};
        out.x = v[0]; out.y = v[1]; out.z = v[2];
        return out;
    }

    // ────────────────────────────────────────────────────────────────────
    //  view_translation singleton — find via heap AOB, then cache
    // ────────────────────────────────────────────────────────────────────
    //   The first call is slow (full heap sweep). Subsequent calls verify
    //   the cached pointer's vtable is still in the module and return
    //   the cached value instantly. Re-scans automatically when the
    //   vtable check fails (between matches).
    // ── Persistent cache (survives cheat restarts) ──────────────────────
    //
    // We cache TWO things:
    //   1. STATIC RVA in the module's .data section that holds a pointer
    //      to the view_translation singleton. On every subsequent run we
    //      can resolve VT in 1 driver call (read [base + RVA]) — INSTANT.
    //   2. The absolute VT address from the last session as a backup.
    //
    // The static RVA is found by scanning .data after the first heap AOB
    // hit and recording any qword that equals the VT pointer. As long as
    // the .data layout of the build hasn't moved, this RVA stays stable
    // across game restarts and sessions.
    struct vt_cache_t {
        uint64_t magic;        // 'SR6V' = valid
        uint64_t static_rva;   // [module_base + static_rva] = VT*
        uint64_t last_addr;    // last session's absolute VT (fallback)
    };
    inline constexpr uint64_t VT_CACHE_MAGIC = 0x5356365253ULL;  // 'SR6VS'

    inline std::string vt_cache_path() {
        char buf[MAX_PATH] = {};
        DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return std::string();
        std::string p = buf;
        p += "\\SlopedR6";
        CreateDirectoryA(p.c_str(), nullptr);
        p += "\\vt.cache";
        return p;
    }
    inline bool load_cached_vt(vt_cache_t& out) {
        auto p = vt_cache_path();
        if (p.empty()) return false;
        HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        DWORD got = 0;
        BOOL ok = ReadFile(f, &out, sizeof(out), &got, nullptr);
        CloseHandle(f);
        return ok && got == sizeof(out) && out.magic == VT_CACHE_MAGIC;
    }
    inline void save_cached_vt(uint64_t static_rva, uint64_t last_addr) {
        auto p = vt_cache_path();
        if (p.empty()) return;
        HANDLE f = CreateFileA(p.c_str(), GENERIC_WRITE, 0,
                               nullptr, CREATE_ALWAYS, 0, nullptr);
        if (f == INVALID_HANDLE_VALUE) return;
        vt_cache_t c{ VT_CACHE_MAGIC, static_rva, last_addr };
        DWORD wrote = 0;
        WriteFile(f, &c, sizeof(c), &wrote, nullptr);
        CloseHandle(f);
    }

    // ────────────────────────────────────────────────────────────────────
    //  resolve_view_translation — disk cache → parallel heap scan.
    // ────────────────────────────────────────────────────────────────────
    //
    //   Two paths only:
    //     (a) Cache hit  — last session's address still valid → instant.
    //     (b) Heap scan  — VirtualQueryEx-driven, multi-threaded, big
    //                      chunk reads. Pattern: VT vtable absolute
    //                      address (8 bytes, qword-aligned). The vtable
    //                      sits at offset 0 of the singleton, so a hit
    //                      IS the singleton address.
    //
    //   All the legacy paths (.text sig decode, .data static-pointer scan,
    //   multi-band tier-by-tier sweep) were ripped out — MCP-verified that
    //   no static pointer to VT exists in this build, and the .text load
    //   pattern shifted enough that none of the sigs match. The single
    //   parallel scan is faster AND more reliable than the chained
    //   discovery we used to do.

    // ── Camera + VP matrix read (used by sample_vt below + view thread) ─
    struct camera_frame_t {
        float     vp[16] = {};
        vector3_t camera = {};
    };

    inline camera_frame_t read_camera_frame_from_vt(uint64_t vt_base) {
        camera_frame_t f;
        if (!is_valid_ptr(vt_base)) return f;
        // SINGLE driver read covering both camera (+0x1D0) and VP matrix
        // (+0x290). One WM_COPYDATA round-trip instead of two.
        constexpr uint64_t SPAN_LO = offsets::VT_CAMERA_POS;          // 0x1D0
        constexpr uint64_t SPAN_HI = offsets::VT_VP_MATRIX + 64;      // 0x2D0
        constexpr size_t   SPAN    = (size_t)(SPAN_HI - SPAN_LO);     // 0x100
        uint8_t buf[SPAN] = {};
        if (!read_bytes(vt_base + SPAN_LO, buf, SPAN)) return f;

        const float* cam = (const float*)(buf + (offsets::VT_CAMERA_POS - SPAN_LO));
        const float* vp  = (const float*)(buf + (offsets::VT_VP_MATRIX  - SPAN_LO));
        f.camera.x = cam[0]; f.camera.y = cam[1]; f.camera.z = cam[2];
        memcpy(f.vp, vp, sizeof(f.vp));
        return f;
    }
}  // namespace r6::decrypt

// ── r6::view_inline_read implementation ─────────────────────────────────
// Defined in the r6 namespace after r6_decrypt.h's helpers are available.
// Gives the render thread a way to do a SINGLE driver call per frame for
// the freshest possible camera/VP — no view-thread, no seqlock latency.
namespace r6 {
    inline bool view_inline_read(float out_vp[16], vector3_t& out_cam) {
        uint64_t vt = g_vt_pointer.load(std::memory_order_acquire);
        if (!vt) return false;
        auto cf = decrypt::read_camera_frame_from_vt(vt);
        if (!cf.camera.is_valid() &&
            cf.vp[0] == 0.0f && cf.vp[5] == 0.0f) {
            return false;
        }
        memcpy(out_vp, cf.vp, sizeof(cf.vp));
        out_cam = cf.camera;
        return true;
    }
}

namespace r6::decrypt {

    // Sample a single candidate's camera/VP. Used by pick_active_vt to
    // score candidates by "freshness" (how often values change).
    struct vt_sample_t {
        vector3_t camera;
        float     vp_diag[4];   // m[0], m[5], m[10], m[15] — sufficient to detect any change
        bool      ok;
    };

    inline vt_sample_t sample_vt(uint64_t vt_addr) {
        vt_sample_t s{};
        camera_frame_t cf = read_camera_frame_from_vt(vt_addr);
        s.camera = cf.camera;
        s.vp_diag[0] = cf.vp[0];
        s.vp_diag[1] = cf.vp[5];
        s.vp_diag[2] = cf.vp[10];
        s.vp_diag[3] = cf.vp[15];
        s.ok = (cf.camera.is_valid()) ||
               (cf.vp[0] != 0.0f || cf.vp[5] != 0.0f);
        return s;
    }

    // Pick the most "active" VT from a candidate list by sampling each
    // a couple times over a short window and scoring how much its
    // camera/VP changed. The active player POV camera updates every
    // frame as the user looks around; inactive VTs (ADS scope when
    // not scoped, spectator when not spectating) sit frozen.
    //
    // Returns the address of the winner, or 0 if none look active.
    inline uint64_t pick_active_vt(const std::vector<uint64_t>& candidates,
                                   int sample_count = 10,
                                   int sample_interval_ms = 50)
    {
        if (candidates.empty()) return 0;
        if (candidates.size() == 1) return candidates[0];

        // Prime: take an initial snapshot of each candidate.
        std::vector<vt_sample_t> prev(candidates.size());
        std::vector<int>         changes(candidates.size(), 0);
        std::vector<bool>        valid(candidates.size(), false);

        for (size_t i = 0; i < candidates.size(); ++i) {
            prev[i] = sample_vt(candidates[i]);
            valid[i] = prev[i].ok;
        }

        // Take subsequent snapshots; count any candidate whose
        // camera position OR any VP diagonal changed.
        for (int s = 0; s < sample_count; ++s) {
            Sleep((DWORD)sample_interval_ms);
            for (size_t i = 0; i < candidates.size(); ++i) {
                vt_sample_t cur = sample_vt(candidates[i]);
                if (!cur.ok) continue;
                bool changed =
                    (cur.camera.x != prev[i].camera.x) ||
                    (cur.camera.y != prev[i].camera.y) ||
                    (cur.camera.z != prev[i].camera.z) ||
                    (cur.vp_diag[0] != prev[i].vp_diag[0]) ||
                    (cur.vp_diag[1] != prev[i].vp_diag[1]) ||
                    (cur.vp_diag[2] != prev[i].vp_diag[2]) ||
                    (cur.vp_diag[3] != prev[i].vp_diag[3]);
                if (changed) ++changes[i];
                prev[i] = cur;
                valid[i] = true;
            }
        }

        // Winner = the valid candidate with the most changes. If
        // nothing changed (player perfectly still + standing still),
        // fall back to the first valid candidate.
        int best_idx = -1;
        int best_changes = -1;
        for (size_t i = 0; i < candidates.size(); ++i) {
            if (!valid[i]) continue;
            LOG_INFO("VT cand[%zu] @ 0x%llX  changes=%d  cam=(%.2f,%.2f,%.2f)",
                     i, (unsigned long long)candidates[i], changes[i],
                     prev[i].camera.x, prev[i].camera.y, prev[i].camera.z);
            if (changes[i] > best_changes) {
                best_changes = changes[i];
                best_idx = (int)i;
            }
        }
        if (best_idx < 0) return 0;
        return candidates[best_idx];
    }

    inline uint64_t resolve_view_translation(uintptr_t module_base, cached_keys_t& keys) {
        const uint64_t vt_vtable_abs =
            (uint64_t)module_base + offsets::VT_VTABLE_RVA;

        auto validate = [&](uint64_t addr) -> bool {
            if (addr < 0x10000ULL || addr >= 0x800000000000ULL) return false;
            uint64_t vt = rpm<uint64_t>(addr);
            return vt >= module_base && vt < module_base + 0x20000000ULL;
        };

        // 1) In-memory cache (already-resolved this session)
        if (keys.view_translation && validate(keys.view_translation))
            return keys.view_translation;
        keys.view_translation = 0;

        // 2) Disk cache: try its candidate list first (instant), then
        //    pick the active one. If the disk cache only has a single
        //    last_addr (legacy format), fall back to using it directly.
        vt_cache_t cache{};
        if (load_cached_vt(cache) && cache.last_addr && validate(cache.last_addr)) {
            // We don't persist the full candidate list across sessions
            // (yet), but the disk-cached single address is a reasonable
            // hot-start. If it's the wrong VT, the user can hit "Try
            // next view" to cycle, OR a re-scan will happen on game
            // restart and pick the most-active automatically.
            keys.view_translation = cache.last_addr;
            keys.vt_candidates    = { cache.last_addr };
            keys.vt_index         = 0;
            LOG_INFO("VT INSTANT from disk cache: 0x%llX (single candidate)",
                     cache.last_addr);
            return cache.last_addr;
        }

        // 3) Parallel heap scan — collect EVERY match, not just the first.
        LOG_INFO("VT cache miss — scanning heap for ALL instances of vtable 0x%llX",
                 vt_vtable_abs);
        auto candidates = parallel_heap_scan_all_singletons(vt_vtable_abs, 16);
        if (candidates.empty()) {
            LOG_ERROR("VT scan failed — no object with vtable 0x%llX found in heap.",
                      vt_vtable_abs);
            return 0;
        }

        // 4) Pick the most-active candidate by live-sampling.
        uint64_t hit = pick_active_vt(candidates);
        if (!hit) hit = candidates[0];

        keys.vt_candidates   = std::move(candidates);
        keys.view_translation = hit;
        // Find chosen index in candidate list for UI cycling.
        for (size_t i = 0; i < keys.vt_candidates.size(); ++i) {
            if (keys.vt_candidates[i] == hit) { keys.vt_index = i; break; }
        }
        LOG_INFO("VT picked: 0x%llX (index %zu of %zu candidates)",
                 hit, keys.vt_index, keys.vt_candidates.size());
        save_cached_vt(0, hit);
        return hit;
    }

    // Cycle to the next VT candidate. Used by the "Try next view"
    // Settings button when the auto-picker chose wrong (e.g. user
    // scoped during the picker's sample window so the scope camera
    // looked more "active" than the player POV).
    inline uint64_t cycle_view_translation(cached_keys_t& keys) {
        if (keys.vt_candidates.empty()) return 0;
        keys.vt_index = (keys.vt_index + 1) % keys.vt_candidates.size();
        keys.view_translation = keys.vt_candidates[keys.vt_index];
        save_cached_vt(0, keys.view_translation);
        LOG_INFO("VT cycled to 0x%llX (index %zu of %zu)",
                 (unsigned long long)keys.view_translation,
                 keys.vt_index, keys.vt_candidates.size());
        return keys.view_translation;
    }

    // (camera_frame_t + read_camera_frame_from_vt are now defined
    //  earlier, just above sample_vt, so pick_active_vt can use them.)

    // Legacy signature: gm-based callers route through the cached
    // view_translation if they pass a base alongside (not great, but
    // keeps the existing reader thread compiling without refactoring).
    inline camera_frame_t read_camera_frame(uint64_t /*gm*/) { return {}; }

    inline vector3_t read_camera(uint64_t /*gm*/) { return {}; }

    inline void read_vp_matrix(uint64_t /*gm*/, float out[16]) {
        memset(out, 0, sizeof(float) * 16);
    }

} // namespace r6::decrypt
