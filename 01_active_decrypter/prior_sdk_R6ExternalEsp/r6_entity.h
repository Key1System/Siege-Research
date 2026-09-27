#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <mutex>
#include <atomic>
#include "r6_math.h"

/*
 * ============================================================================
 *  r6_entity.h — Entity data structures and double-buffered cache
 * ============================================================================
 *
 *  The background reader thread writes to one buffer while the render
 *  thread reads from the other. An atomic pointer swap ensures lock-free
 *  reads on the render side.
 * ============================================================================
 */

namespace r6 {

    // ── Freeze detection config ─────────────────────────────────────────
    // Entities that haven't moved for FREEZE_HIDE_TIME seconds are hidden
    // (likely dead, disconnected, or bugged).

    inline constexpr float  FREEZE_THRESHOLD = 0.001f;
    inline constexpr double FREEZE_HIDE_TIME = 10.0;

    // ── Per-entity snapshot ─────────────────────────────────────────────

    struct entity_t {
        vector3_t position  = {};
        vector3_t velocity  = {};       // computed from position deltas
        float     distance  = 0.0f;     // distance from camera
        bool      is_local  = false;    // local player (you)
        bool      is_team   = false;    // squadmate
        bool      is_dead   = false;    // corpse / disconnected
        uint64_t  entity_ptr    = 0;    // ENT1 heap address (stable per-match)
        uint64_t  transform_ptr = 0;    // ENT2 / transform_obj heap address
        int32_t   role_id    = 0;       // ENT1+0x1C; same value for every
                                        // alias of the same player so we
                                        // can dedupe at snapshot time.
        double    last_update   = 0.0;
        double    frozen_since  = 0.0;

        bool is_frozen() const {
            return frozen_since > 0.0 &&
                   (last_update - frozen_since) > FREEZE_HIDE_TIME;
        }
    };

    // ── Frame snapshot (what the render thread consumes) ────────────────

    struct entity_cache_t {
        std::vector<entity_t> entities;
        float     vp[16]   = {};        // view-projection matrix
        vector3_t camera    = {};
        double    timestamp = 0.0;
    };

    // ── Entity cache double buffer ──────────────────────────────────────
    // g_read  = render thread reads from this (atomic, lock-free)
    // g_write = background thread writes to this, then swaps
    // g_swap_lock protects the swap itself (very short critical section)

    inline entity_cache_t                g_buf_a, g_buf_b;
    inline std::atomic<entity_cache_t*>  g_read{ &g_buf_a };
    inline entity_cache_t*               g_write = &g_buf_b;
    inline std::mutex                    g_swap_lock;

    // Swap write -> read atomically
    inline void swap_buffers() {
        std::lock_guard<std::mutex> lk(g_swap_lock);
        auto* old_read = g_read.load(std::memory_order_relaxed);
        g_read.store(g_write, std::memory_order_release);
        g_write = old_read;
    }

    // ── Fast-path view cache (updated at 125 Hz by view_thread) ─────────
    //
    // Camera position + view-projection matrix get refreshed much faster
    // than the full entity walk so the ESP can re-project at every render
    // frame using a near-current camera angle. This is what kills the
    // "boxes jump when I move my camera" jitter.
    //
    // Seqlock pattern: writer bumps `seq` to odd, writes, bumps to even.
    // Reader snapshots seq, reads data, re-checks seq — if both are equal
    // AND even, the read is consistent. Otherwise retry.
    struct view_state_t {
        std::atomic<uint64_t> seq{ 0 };
        float                 vp[16] = {};
        vector3_t             camera = {};
    };
    inline view_state_t g_view;

    // VT singleton pointer, owned by the reader, read by render. When
    // populated, the render thread can do an inline driver read to
    // get sub-millisecond-fresh camera/VP — no view-thread scheduling
    // jitter, no seqlock TTL. Falls back to the seqlock if 0.
    inline std::atomic<uint64_t> g_vt_pointer{ 0 };

    inline void view_publish(const float vp[16], const vector3_t& cam) {
        uint64_t s = g_view.seq.load(std::memory_order_relaxed);
        g_view.seq.store(s + 1, std::memory_order_release);  // begin write (odd)
        memcpy(g_view.vp, vp, sizeof(g_view.vp));
        g_view.camera = cam;
        g_view.seq.store(s + 2, std::memory_order_release);  // end write (even)
    }

    // Forward declaration; defined in r6_decrypt.h after the offsets +
    // driver helpers are available.
    inline bool view_inline_read(float out_vp[16], vector3_t& out_cam);

    inline void view_snapshot(float out_vp[16], vector3_t& out_cam) {
        // Fast path: inline driver read using the published VT pointer.
        // Single 256-byte WM_COPYDATA round-trip — at 240 FPS this is
        // 240 calls/sec, trivial vs the 1000+/sec the bridge can sustain.
        // The render thread reads the camera that was JUST captured; no
        // view-thread scheduling jitter, no seqlock TTL.
        if (view_inline_read(out_vp, out_cam)) return;

        // Fallback: seqlock published by the (legacy) view thread. Used
        // until the reader resolves VT for the first time.
        for (;;) {
            uint64_t s1 = g_view.seq.load(std::memory_order_acquire);
            if (s1 & 1) continue;                            // writer mid-update
            memcpy(out_vp, g_view.vp, sizeof(g_view.vp));
            out_cam = g_view.camera;
            uint64_t s2 = g_view.seq.load(std::memory_order_acquire);
            if (s1 == s2) return;                            // consistent
            // else: retry
        }
    }

} // namespace r6
