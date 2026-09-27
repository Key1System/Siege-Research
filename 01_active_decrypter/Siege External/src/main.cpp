// Siege External — usermode read-only ESP for R6 Siege.
// Boot sequence (all logged to console):
//   1. Starting up
//   2. Attaching to RainbowSix.exe
//   3. Locating ViewData (camera + view-projection matrix)
//   4. Loading ImGui overlay
//   5. Enumerating entities (hknpCharacterRigidBody)
//   6. Main loop: refresh matrix + positions, draw boxes
//
// Scope: local, single-machine, read-only. No writes, no injections.

#include "core/proc.h"
#include "core/mem.h"
#include "core/scan.h"
#include "game/view.h"
#include "game/cache.h"
#include "game/bones.h"
#include "game/bones_cache.h"
#include "game/offsets.h"
#include "overlay/overlay.h"
#include "overlay/menu.h"
#include "settings/settings.h"
#include "esp/esp.h"
#include "../third_party/imgui/imgui.h"

// Exposed by menu.cpp — the "unload flag" the vast menu writes when the
// user right-clicks the brand text.
namespace recode { extern std::atomic_bool is_running; }

#include <Windows.h>
#include <cstdio>
#include <chrono>
#include <thread>
#include <atomic>
#include <mutex>
#include <unordered_map>

static void log(const char* fmt, ...) {
    printf("[SiegeExt] ");
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

int main() {
    log("=====================================");
    log("Siege External — starting up");
    log("=====================================");

    // Turn on scan progress logs (one line per 128 MB scanned).
    core::scan_debug().store(true);

    // 1. Attach.
    log("Attaching to RainbowSix.exe ...");
    core::Proc proc{};
    while (!core::attach(L"RainbowSix.exe", proc)) {
        log("  RainbowSix.exe not found — retrying in 2 s");
        std::this_thread::sleep_for(std::chrono::seconds(2));
    }
    log("  attached: pid=%u  base=0x%llX  size=0x%llX",
        proc.pid, (unsigned long long)proc.main.base,
        (unsigned long long)proc.main.size);
    log("  hwnd=0x%p", (void*)proc.hwnd);

    // 2. Locate ViewData (camera + view-projection).
    // Disk cache keyed by module base: once we've located ViewData for
    // a session, future launches with the same base skip the scan and
    // reuse it directly.
    log("Locating ViewData signature ...");
    game::ViewData vd{};
    auto vd_res = game::find_view_data_cached(proc.handle, proc.main.base);
    vd.base = vd_res.base;
    if (!vd.base) {
        log("  FAILED — pattern not found. Are you in-match or firing range?");
        log("  Press ENTER to exit.");
        (void)getchar();
        return 1;
    }
    const char* src_lbl = "(unknown)";
    switch (vd_res.source) {
        case game::ViewDataSource::Cache: src_lbl = "(via disk cache)"; break;
        case game::ViewDataSource::Scan:  src_lbl = "(via pattern scan — cached for next run)"; break;
        default: break;
    }
    log("  ViewData found at 0x%llX  %s",
        (unsigned long long)vd.base, src_lbl);
    log("  camera position slot = ViewData + 0x%X", (int)game::VD_CAM_POS_OFF);
    log("  view-projection slot = ViewData + 0x%X", (int)game::VD_VIEW_PROJ_OFF);

    if (!game::refresh(proc.handle, vd)) {
        log("  FAILED to read ViewData contents");
        return 1;
    }
    log("  camera=(%.2f, %.2f, %.2f)  vp[15]=%.4f",
        vd.cam_pos.x, vd.cam_pos.y, vd.cam_pos.z, vd.view_proj.m[15]);

    // 3. Overlay.
    log("Loading ImGui overlay ...");
    overlay::Overlay ov{};
    if (!overlay::create(ov, proc.hwnd)) {
        log("  FAILED to create overlay");
        return 1;
    }
    log("  overlay window created: %dx%d", ov.width, ov.height);

    // 4. Entity enumeration.
    // Live-verified strategy (via Bytecode 2026-07-17):
    //   - CharacterControllers (CCs) are stable, long-lived objects
    //   - Bodies churn — their addresses change as they recycle
    //   - So we scan for vt_cc directly, filter to real CCs by checking
    //     that CC+0 points to something with vt = vt_body
    //   - CC addresses are cached to disk; next launch restores instantly
    //     as long as the module base matches (i.e. R6 wasn't restarted)
    uint64_t vt_body = game::offsets::vt_hknp_character_body(proc.main.base);
    uint64_t vt_cc   = game::offsets::vt_rigidbody_cc(proc.main.base);
    log("Entity resolution ...");
    log("  vt_body = 0x%llX", (unsigned long long)vt_body);
    log("  vt_cc   = 0x%llX", (unsigned long long)vt_cc);

    game::EntityCache cache;
    std::mutex cache_mtx;
    std::atomic<bool> shutdown{false};
    std::atomic<bool> first_rebuild_done{false};

    // Bone / SkelComp state — updated on its own background thread every
    // few seconds. Held under `bones_mtx` since render + updater both
    // touch it.
    std::vector<game::Character> bone_chars;
    std::mutex bones_mtx;
    uint64_t vt_subentry = game::offsets::vt_skel_subentry(proc.main.base);
    log("  vt_skel = 0x%llX", (unsigned long long)vt_subentry);

    // Load disk cache — CCs + hot arenas from a prior run.
    game::CcCache disk_cache = game::cc_cache_read(proc.main.base, vt_cc);
    std::vector<game::Arena> hot_arenas = disk_cache.arenas;

    if (!disk_cache.ccs.empty()) {
        log("  disk cache: %zu CCs, %zu hot arenas",
            disk_cache.ccs.size(), hot_arenas.size());
        std::lock_guard<std::mutex> lk(cache_mtx);
        size_t restored = cache.install_from_cache(proc.handle, disk_cache.ccs,
                                                   vt_cc, vt_body);
        log("  restored %zu / %zu entities from disk cache",
            restored, disk_cache.ccs.size());
        if (restored > 0) first_rebuild_done.store(true);
    } else {
        log("  no disk cache (or module base changed)");
    }

    // Rebuild-needed flag — flipped by the render loop when a CC
    // becomes stale (character died / respawned into a new CC address).
    std::atomic<bool> needs_rebuild{!first_rebuild_done.load()};

    std::thread scanner([&, vt_body, vt_cc, disk_cache]() {
        std::vector<game::Arena> arenas = disk_cache.arenas;

        while (!shutdown.load()) {
            if (needs_rebuild.exchange(false)) {
                game::EntityCache tmp;
                auto rr = tmp.rebuild(proc.handle, vt_body, vt_cc,
                                       arenas, /*workers=*/8);

                auto ccs = tmp.cc_addresses();
                if (!rr.hot_arenas.empty()) {
                    arenas = rr.hot_arenas;
                }
                {
                    std::lock_guard<std::mutex> lk(cache_mtx);
                    cache = std::move(tmp);
                }
                if (!first_rebuild_done.load()) {
                    log("  first rebuild: %zu entities in %llu ms (%llu MB scanned)",
                        ccs.size(),
                        (unsigned long long)rr.scan_ms,
                        (unsigned long long)(rr.scanned_bytes >> 20));
                    for (uint64_t cc : ccs) {
                        log("    cc=0x%llX", (unsigned long long)cc);
                    }
                    first_rebuild_done.store(true);
                }
                if (!ccs.empty()) {
                    game::cc_cache_write(proc.main.base, vt_cc, arenas, ccs);
                }
            }
            // Idle sleep — the render loop signals when it needs a rebuild.
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    // 4b. Bone scanner — first pass enumerates SkelComps by scan; every
    //     subsequent pass just re-reads the SAME SkelComp addresses at
    //     ~10 Hz. Logs "MOVED" if any bone's translation changed since
    //     the last read. This is the diagnostic that tells us whether
    //     these bone slots are static bind-pose (recon §16e claim) or
    //     actually animated per-frame.
    std::thread bone_scanner([&, vt_subentry]() {
        while (!shutdown.load() && !first_rebuild_done.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(200));

        std::vector<uint64_t> skel_addrs;
        std::vector<game::Character> prev_chars;

        while (!shutdown.load()) {
            std::vector<uint64_t> ccs;
            {
                std::lock_guard<std::mutex> lk(cache_mtx);
                ccs = cache.cc_addresses();
            }
            if (ccs.empty()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
                continue;
            }

            std::vector<game::Character> chars;
            if (skel_addrs.empty()) {
                // First time: full enum (slow ~2-5s, one-time).
                chars = game::enumerate_skeletons(
                    proc.handle, vt_subentry, ccs);
                for (const auto& c : chars) skel_addrs.push_back(c.skel_comp);
                log("  bone scanner: first enum %zu SkelComps", chars.size());
            } else {
                // Every subsequent tick: re-read the cached addresses.
                // Cheap: ~a few hundred RPMs total.
                chars = game::skeletons_from_addrs(
                    proc.handle, skel_addrs, ccs);
            }

            // ── Motion scoring ──────────────────────────────────────
            // For each SkelComp + bone slot-index, keep a rolling
            // motion score that INCREASES when the local translation
            // changes and DECAYS every tick. Static junk slots settle
            // near 0; real animated bones sit above a threshold.
            //
            // Key is (skel_comp << 16) | slot_index — unique per bone.
            static std::unordered_map<uint64_t, float> motion_map;
            static int decay_ticks = 0;

            if (!prev_chars.empty()) {
                for (size_t i = 0; i < chars.size(); ++i) {
                    // Find matching prev by skel_comp
                    const game::Character* prev = nullptr;
                    for (const auto& p : prev_chars)
                        if (p.skel_comp == chars[i].skel_comp) { prev = &p; break; }
                    if (!prev) continue;
                    for (auto& b : chars[i].bones) {
                        // Find previous slot with same index
                        const game::Bone* pb = nullptr;
                        for (const auto& x : prev->bones)
                            if (x.index == b.index) { pb = &x; break; }
                        if (!pb) continue;
                        float dy = b.local_trans.y - pb->local_trans.y;
                        float dz = b.local_trans.z - pb->local_trans.z;
                        float d  = std::abs(dy) + std::abs(dz);
                        uint64_t key = (chars[i].skel_comp << 16) | (uint64_t)(b.index & 0xFFFF);
                        float& s = motion_map[key];
                        s = 0.9f * s + d;              // rolling accumulator w/ decay
                        b.motion_score = s;
                    }
                }
            }
            // Global slow decay so scores don't accumulate forever if a
            // character stops moving.
            if (++decay_ticks >= 200) {  // ~1 sec at 5 ms tick
                for (auto& kv : motion_map) kv.second *= 0.5f;
                decay_ticks = 0;
            }
            // Propagate score to bones we just read (so render sees it).
            for (auto& ch : chars) {
                for (auto& b : ch.bones) {
                    uint64_t key = (ch.skel_comp << 16) | (uint64_t)(b.index & 0xFFFF);
                    auto it = motion_map.find(key);
                    if (it != motion_map.end()) b.motion_score = it->second;
                }
            }
            prev_chars = chars;

            {
                std::lock_guard<std::mutex> lk(bones_mtx);
                bone_chars = std::move(chars);
            }

            // ~200 Hz refresh — matches frame cadence so ESP tracks
            // 1:1 with the game's animation output.
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    });

    // 5. Main loop — draws IMMEDIATELY. First few seconds have no ESP boxes
    //    (cache empty), but the ImGui overlay itself is visible.
    log("Entering main loop. Ctrl+C to exit.");
    esp::Config cfg{};
    bool running = true;
    auto last_stats = std::chrono::steady_clock::now();
    int  frames = 0;

    while (running) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) running = false;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        if (!IsWindow(proc.hwnd)) { log("target hwnd gone — exit"); break; }
        if (!recode::is_running.load()) { log("unload requested via menu"); break; }
        overlay::follow(ov, proc.hwnd);
        game::refresh(proc.handle, vd);

        // O key toggles the menu (edge-triggered). Also swap
        // WS_EX_TRANSPARENT so the overlay accepts mouse when menu is open.
        if (GetAsyncKeyState('O') & 1) {
            settings::menu_key = !settings::menu_key;
            overlay::set_menu_input(ov, settings::menu_key);
            log("O -> menu_key=%s", settings::menu_key ? "ON" : "OFF");
        }

        // Per-frame: refresh CC positions AND detect stale CCs.
        // A stale CC (vt @ +0x10 != vt_cc) means the character died
        // and their memory got recycled — kick off a rebuild.
        {
            std::lock_guard<std::mutex> lk(cache_mtx);
            bool stale = false;
            cache.refresh_positions(proc.handle, vt_cc, vt_body, stale);
            if (stale) needs_rebuild.store(true);
        }
        // Periodic rebuild to pick up newly-spawned characters.
        static auto last_periodic_rebuild = std::chrono::steady_clock::now();
        auto now_pr = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(
                now_pr - last_periodic_rebuild).count() >= 3) {
            needs_rebuild.store(true);
            last_periodic_rebuild = now_pr;
        }

        // Present(0) = uncapped. Present(1) = vsync.
        int vsync = settings::overlay_vsync ? 1 : 0;

        overlay::draw(ov, [&]() {
            std::lock_guard<std::mutex> lk(cache_mtx);
            // Always-on watermark (top-left).
            L7Menu::DrawWatermark();
            // The menu itself (only if user pressed O).
            if (settings::menu_key) {
                L7Menu::menu();
                input();
            }
            // ESP boxes always on.
            esp::render(cache, vd, cfg, (float)ov.width, (float)ov.height);
            // Bones + indices — separate lock, may lag behind if bone
            // scanner is mid-sweep.
            {
                std::lock_guard<std::mutex> bl(bones_mtx);
                esp::render_bones(bone_chars, vd, cfg,
                                  (float)ov.width, (float)ov.height);
            }
        }, vsync);

        ++frames;
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                            now - last_stats).count();
        if (elapsed >= 5) {
            log("  fps=%d  entities=%zu",
                frames / (int)elapsed, cache.entities().size());
            frames = 0;
            last_stats = now;
        }
    }

    shutdown.store(true);
    if (scanner.joinable()) scanner.join();
    if (bone_scanner.joinable()) bone_scanner.join();

    overlay::destroy(ov);
    core::detach(proc);
    log("bye.");
    return 0;
}
