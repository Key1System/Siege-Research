// crypto/watch.cpp — live discovery loop implementation.
#include "watch.h"
#include "site_registry.h"
#include "tls.h"
#include "decrypter.h"
#include "decrypt_t1.h"
#include "decrypt_t3.h"
#include "decrypt_t4.h"
#include "decrypt_t7.h"

#include <Windows.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace crypto::watch {

namespace {

std::atomic<bool>  g_running{false};
std::atomic<bool>  g_kick{false};
std::thread        g_thread;
uint32_t           g_interval_ms = 2000;
uint32_t           g_cycle = 0;

// TLS-key drift tracker. key = TLS offset; value = last-seen qword.
// If value changes between cycles, log it.
std::unordered_map<uint32_t, uint64_t> g_tls_seen;

void put(const char* fmt, ...) {
    printf("[watch] ");
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

// ── Per-section helpers ────────────────────────────────────────────

void report_header() {
    printf("\n");
    put("============================================================");
    put("R6 crypto watch  ·  cycle #%u", g_cycle);
    put("============================================================");
}

// Enumerate every TLS offset any site uses, sorted, deduped.
std::vector<uint32_t> collect_tls_offsets() {
    std::vector<uint32_t> offs;
    for (size_t i = 0; i < crypto::site_count(); ++i) {
        const auto* s = crypto::site_at(i);
        if (!s) continue;
        if (s->tls_off == 0) continue;
        offs.push_back(s->tls_off);
    }
    // Add known keys from the recon MD that aren't yet in a site row.
    // These get read even if no registered site references them yet.
    static const uint32_t known_extras[] = {
        0x1C,       // thread-init flag
        0x3A50,     // T5 rot
        0x3C80,     // T5 xor key
        0x6C90,     // task-queue free-list head
        0x70A0,     // crypto key A
        0x8DE0,     // entity-handle decrypt key
        0x8E60, 0x8E80, 0x8EA0,   // sibling keys
        0x9D08, 0x9D40, 0x9D68,   // SkelComp init keys
    };
    for (uint32_t o : known_extras) offs.push_back(o);

    std::sort(offs.begin(), offs.end());
    offs.erase(std::unique(offs.begin(), offs.end()), offs.end());
    return offs;
}

void report_tls_keys() {
    crypto::tls::Snapshot snap;
    put("--- TLS keys ---");
    if (!snap.valid()) {
        put("  (TLS block unavailable — TlsIndex ptr not set or thread has no TLS)");
        return;
    }
    put("  block base    = 0x%p", (void*)snap.block);

    auto offs = collect_tls_offsets();
    int changed = 0;
    for (uint32_t o : offs) {
        uint64_t v = snap.qword(o);
        auto it = g_tls_seen.find(o);
        const char* tag = "     ";
        if (it == g_tls_seen.end()) {
            tag = "NEW  ";
        } else if (it->second != v) {
            tag = "CHG  ";
            ++changed;
        }
        g_tls_seen[o] = v;
        // Compact log — one line per key showing hex qword + as rotate amount
        // + as int32 low.
        put("  %s TLS[0x%05X]  q=0x%016llX  rot=%u  i32=%d",
            tag, o,
            (unsigned long long)v,
            (unsigned)(v & 0x3F),
            (int)(int32_t)(v & 0xFFFFFFFF));
    }
    if (changed) put("  ** %d key(s) changed since last cycle **", changed);
}

void report_sites() {
    put("--- registered sites (%zu) ---", crypto::site_count());
    for (size_t i = 0; i < crypto::site_count(); ++i) {
        const auto* s = crypto::site_at(i);
        if (!s) continue;
        // Only run "sample decrypts" for sites that can operate on a
        // synthetic ciphertext with the currently-available TLS keys.
        // T3 needs K1..K3 (we have those inline). T7 needs K + TLS.
        // T1 too. T4 too. T5 is HealthState — needs a real DamageComp.
        // T2 needs a trampoline probe.
        //
        // The "sample" is: decrypt a well-known test qword and print
        // the result. This is a smoke test that proves the site's
        // math executes cleanly with the current TLS state.

        const uint64_t sample_enc = 0xDEADBEEFCAFEBABEULL;
        uint64_t plain = 0;
        const char* tmpl_name = "?";
        switch (s->tmpl) {
            case crypto::Template::T1_TlsRotMbaPure:
                tmpl_name = "T1_TlsRotMBA";
                plain = crypto::t1::decrypt(sample_enc, s->tls_off);
                break;
            case crypto::Template::T3_XorAddXor:
                tmpl_name = "T3_XorAddXor";
                if (s->k1 || s->k2 || s->k3)
                    plain = crypto::t3::decrypt(sample_enc, s->k1, s->k2, s->k3);
                break;
            case crypto::Template::T4_TlsSubXor:
                tmpl_name = "T4_TlsSubXor";
                if (s->k1)
                    plain = crypto::t4::decrypt(sample_enc, s->tls_off, s->k1);
                break;
            case crypto::Template::T5_HealthState:
                tmpl_name = "T5_HealthState";
                break;
            case crypto::Template::T6_AnvilHandle:
                tmpl_name = "T6_AnvilHandle";
                break;
            case crypto::Template::T7_TlsRotSingleXor:
                tmpl_name = "T7_TlsRotSingleXor";
                plain = crypto::t7::decrypt(sample_enc, s->k1, s->tls_off);
                break;
            case crypto::Template::T2_StackHashedMba:
                tmpl_name = "T2_StackHashedMba(needs trampoline)";
                break;
            default: break;
        }

        put("  [%u] %s", (unsigned)s->id, tmpl_name);
        put("       name    : %s", s->name ? s->name : "");
        if (s->k1) put("       K1      : 0x%016llX", (unsigned long long)s->k1);
        if (s->k2) put("       K2      : 0x%016llX", (unsigned long long)s->k2);
        if (s->k3) put("       K3      : 0x%016llX", (unsigned long long)s->k3);
        if (s->tls_off) put("       TLS off : 0x%04X", s->tls_off);
        if (plain) {
            put("       sample  : dec(0x%llX) = 0x%016llX",
                (unsigned long long)sample_enc,
                (unsigned long long)plain);
        }
    }
}

// Recon-MD-known encrypted qwords the game keeps somewhere reachable.
// Reading them per cycle gives us LIVE encrypted-value visibility so we
// can watch when the game rotates its ciphertext (which happens each
// tick for T1 physics-step targets, etc.).
struct StaticProbe {
    const char* name;
    uint64_t    rva;     // relative to module base
    int         template_id;   // matches SiteId::* — we decrypt via that
    uint32_t    site_id;
};

// Add probes here as we identify globally-encrypted ciphertexts.
// The vector starts empty at DLL load; add rows via
// crypto::watch::register_probe() at runtime.
static std::vector<StaticProbe>& probes() {
    static std::vector<StaticProbe> v;
    return v;
}

void report_static_probes() {
    put("--- static probes (%zu) ---", probes().size());
    if (probes().empty()) {
        put("  (none registered — add via register_probe() or extend watch.cpp)");
        return;
    }
    HMODULE host = GetModuleHandleW(nullptr);
    uint64_t base = reinterpret_cast<uint64_t>(host);
    for (const auto& p : probes()) {
        uint64_t addr = base + p.rva;
        uint64_t enc = 0;
        __try {
            enc = *reinterpret_cast<const uint64_t*>(addr);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            put("  %-32s @ 0x%llX  <read fault>",
                p.name, (unsigned long long)addr);
            continue;
        }
        auto r = crypto::decrypt(
            static_cast<crypto::SiteId>(p.site_id), enc);
        put("  %-32s @ 0x%llX  enc=0x%016llX  ->  0x%016llX  %s",
            p.name, (unsigned long long)addr,
            (unsigned long long)enc,
            (unsigned long long)r.plain,
            r.ok ? "" : "(decrypt failed)");
    }
}

void report_footer() {
    put("============================================================");
    printf("\n");
    fflush(stdout);
}

void run_one_cycle() {
    ++g_cycle;
    report_header();
    report_tls_keys();
    report_sites();
    report_static_probes();
    report_footer();
}

void watcher_loop() {
    // Run once immediately on startup so users see the report right away.
    run_one_cycle();
    while (g_running.load()) {
        // Sleep in small increments so kick or stop responds quickly.
        for (uint32_t i = 0; i < g_interval_ms && g_running.load(); i += 50) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            if (g_kick.exchange(false)) {
                run_one_cycle();
                break;
            }
        }
        if (!g_running.load()) break;
        run_one_cycle();
    }
}

} // namespace

bool start(uint32_t interval_ms) noexcept {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return false;
    g_interval_ms = interval_ms;
    g_thread = std::thread(watcher_loop);
    g_thread.detach();
    return true;
}

void stop() noexcept {
    g_running.store(false);
}

void report_now() noexcept {
    g_kick.store(true);
}

} // namespace crypto::watch
