// dllmain.cpp — siege_crypto.dll entry point.
//
// On DLL_PROCESS_ATTACH we:
//   1. Locate the game module base (already loaded — we're in-process).
//   2. Resolve TlsIndex pointer (fixed RVA for this build; sig-scan
//      helper for future builds).
//   3. Spin up a console for diagnostics + test output.
//   4. Run the built-in test harness against known-good vectors.
//
// The DLL exports its API via extern "C" (see decrypter.h). Any host
// process (loader, external tool, Lua wrapper) can consume it.
#include "../src/crypto/decrypter.h"
#include "../src/crypto/site_registry.h"
#include "../src/crypto/tls.h"
#include "../src/crypto/decrypt_t1.h"
#include "../src/crypto/decrypt_t3.h"
#include "../src/crypto/decrypt_t4.h"
#include "../src/crypto/server.h"
#include "../src/crypto/watch.h"
#include <Windows.h>
#include <cstdio>
#include <cstdint>
#include <string>

namespace {

// R6 build 0x7FF6FBEB0000 puts TlsIndex at IDB 0x7FF70C6253BC.
// RVA = 0x7FF70C6253BC - 0x7FF6FBEB0000 = 0x107753BC.
constexpr uint64_t IDB_BASE      = 0x7FF6FBEB0000ULL;
constexpr uint64_t IDB_TLS_INDEX = 0x7FF70C6253BCULL;
constexpr uint32_t TLS_INDEX_RVA = static_cast<uint32_t>(IDB_TLS_INDEX - IDB_BASE);

FILE* g_console_out = nullptr;

void open_console() {
    if (AllocConsole()) {
        freopen_s(&g_console_out, "CONOUT$", "w", stdout);
        SetConsoleTitleW(L"siege_crypto");
    }
}

void log_line(const char* fmt, ...) {
    printf("[siege_crypto] ");
    va_list ap; va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    printf("\n");
    fflush(stdout);
}

// ── Test harness — round-trip verify every template's inverse ──────
// For T1/T3/T4 we can encrypt-then-decrypt a known plaintext with
// synthetic keys and confirm we recover the plaintext. This validates
// the math independent of any live game state.
void run_self_tests() {
    log_line("Running self-tests ...");

    // T1 — pick a bogus rot amount (we don't call decrypt/encrypt with
    // the real TLS-backed accessor; instead we test the pure math).
    {
        uint64_t plain = 0x1122334455667788ULL;
        uint8_t  rot   = 21;
        uint64_t enc   = (crypto::rotl64(plain, rot) - crypto::t1::K2) ^ crypto::t1::K1;
        uint64_t x     = (enc ^ crypto::t1::K1) + crypto::t1::K2;
        uint64_t back  = crypto::rotr64(x, rot);
        log_line("  T1 math: plain=0x%llX enc=0x%llX back=0x%llX %s",
                 (unsigned long long)plain, (unsigned long long)enc,
                 (unsigned long long)back, back == plain ? "OK" : "FAIL");
    }

    // T3 — pure formula, no runtime input.
    {
        uint64_t plain = 0xDEADBEEFCAFEBABEULL;
        uint64_t k1 = 0x0F0F0F0F0F0F0F0FULL;
        uint64_t k2 = 0x1234567890ABCDEFULL;
        uint64_t k3 = 0xAAAAAAAAAAAAAAAAULL;
        uint64_t enc = crypto::t3::encrypt(plain, k1, k2, k3);
        uint64_t back = crypto::t3::decrypt(enc, k1, k2, k3);
        log_line("  T3: plain=0x%llX enc=0x%llX back=0x%llX %s",
                 (unsigned long long)plain, (unsigned long long)enc,
                 (unsigned long long)back, back == plain ? "OK" : "FAIL");
    }

    // T4 — depends on TLS but we simulate the TLS read here.
    {
        uint64_t plain   = 0x0102030405060708ULL;
        uint64_t k1      = 0xFFFF0000FFFF0000ULL;
        uint64_t tls_val = 0x00000000CAFEF00DULL;
        // Encrypt: (plain ^ k1) + tls_val   →   Decrypt: (enc - tls_val) ^ k1
        uint64_t enc     = (plain ^ k1) + tls_val;
        uint64_t back    = (enc - tls_val) ^ k1;
        log_line("  T4 math: plain=0x%llX enc=0x%llX back=0x%llX %s",
                 (unsigned long long)plain, (unsigned long long)enc,
                 (unsigned long long)back, back == plain ? "OK" : "FAIL");
    }

    log_line("Self-tests done.");
}

void dump_registry() {
    log_line("Registered sites (%zu):", crypto::site_count());
    for (size_t i = 0; i < crypto::site_count(); ++i) {
        const crypto::SiteInfo* s = crypto::site_at(i);
        if (!s) continue;
        log_line("  [%u] tmpl=%u k1=0x%llX k2=0x%llX k3=0x%llX tls_off=0x%X  %s",
                 static_cast<unsigned>(s->id),
                 static_cast<unsigned>(s->tmpl),
                 (unsigned long long)s->k1,
                 (unsigned long long)s->k2,
                 (unsigned long long)s->k3,
                 s->tls_off,
                 s->name);
    }
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    (void)hInst; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);

        open_console();
        log_line("siege_crypto.dll loaded into pid=%u tid=%u",
                 GetCurrentProcessId(), GetCurrentThreadId());

        // Locate the host module (RainbowSix.exe).
        HMODULE host = GetModuleHandleW(nullptr);
        if (!host) {
            log_line("  FAIL: GetModuleHandleW(nullptr) returned null");
            return TRUE;
        }
        uint64_t base = reinterpret_cast<uint64_t>(host);
        log_line("  host module base = 0x%llX", (unsigned long long)base);

        // Resolve TlsIndex pointer at fixed RVA (for this build).
        uint32_t* tls_index = reinterpret_cast<uint32_t*>(base + TLS_INDEX_RVA);
        log_line("  TlsIndex ptr    = 0x%p (value=%u)",
                 (void*)tls_index, *tls_index);

        // Initialise the decrypter core.
        if (!crypto::init(base, tls_index)) {
            log_line("  FAIL: crypto::init returned false");
            return TRUE;
        }

        // Diagnostics.
        dump_registry();
        run_self_tests();

        // Kick off the HTTP server for Bytecode / curl clients.
        if (crypto::server::start(9998)) {
            log_line("HTTP server started on 127.0.0.1:9998");
            log_line("  GET  /ping");
            log_line("  GET  /sites");
            log_line("  POST /decrypt          {site:N, enc:\"0x...\"}");
            log_line("  POST /decrypt_health   {damage_comp:\"0x...\"}");
            log_line("  POST /tls_read         {off:N}");
            log_line("  POST /watch            (force immediate watch report)");
        } else {
            log_line("WARN: HTTP server failed to start (port 9998 in use?)");
        }

        // Kick off the live watch — periodic report of TLS state +
        // per-site sample decrypts. This turns the DLL from a static
        // decrypter into an active discovery tool.
        if (crypto::watch::start(/*interval_ms=*/3000)) {
            log_line("Live watch started (3 s cycle) — see [watch] lines below");
        }

        log_line("Ready. Use C exports or HTTP to decrypt values live.");
    }
    return TRUE;
}
