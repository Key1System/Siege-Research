// crypto/decrypter.cpp — dispatch + C exports.
#include "decrypter.h"
#include "site_registry.h"
#include "tls.h"
#include "trampoline.h"
#include "decrypt_t1.h"
#include "decrypt_t3.h"
#include "decrypt_t4.h"
#include "decrypt_t5.h"
#include "decrypt_t7.h"
#include <cstdio>
#include <cstring>

namespace crypto {

bool init(uint64_t module_base, uint32_t* tls_index_ptr) {
    if (!tls_index_ptr) return false;
    crypto::tls::set_tls_index_ptr(tls_index_ptr);
    crypto::trampoline::install_probes(module_base);
    return true;
}

Result decrypt(SiteId site, uint64_t enc) {
    const SiteInfo* info = find_site(site);
    if (!info) return Result::fail();

    switch (info->tmpl) {
        case Template::T1_TlsRotMbaPure:
            return Result::of(crypto::t1::decrypt(enc, info->tls_off));

        case Template::T3_XorAddXor:
            return Result::of(crypto::t3::decrypt(enc, info->k1, info->k2, info->k3));

        case Template::T4_TlsSubXor:
            return Result::of(crypto::t4::decrypt(enc, info->tls_off, info->k1));

        case Template::T7_TlsRotSingleXor:
            return Result::of(crypto::t7::decrypt(enc, info->k1, info->tls_off));

        case Template::T2_StackHashedMba:
            // Dispatch by site name — the probe registry uses names.
            return crypto::trampoline::decrypt(info->name, enc);

        case Template::T5_HealthState:
        case Template::T6_AnvilHandle:
        case Template::Invalid:
        default:
            // These aren't 64-bit qword decrypts; caller should use the
            // dedicated helper (decrypt_health for T5; Anvil resolver
            // for T6).
            return Result::fail();
    }
}

void decrypt_batch(SiteId site, const uint64_t* enc, uint64_t* out, size_t n) {
    if (!enc || !out || n == 0) return;
    const SiteInfo* info = find_site(site);
    if (!info) {
        for (size_t i = 0; i < n; ++i) out[i] = 0;
        return;
    }

    // Snapshot TLS once for the batch (T1/T4 need the same rotate key
    // for every element; no reason to re-walk TEB per iteration).
    crypto::tls::Snapshot snap;

    switch (info->tmpl) {
        case Template::T1_TlsRotMbaPure:
            for (size_t i = 0; i < n; ++i)
                out[i] = crypto::t1::decrypt(enc[i], info->tls_off, snap);
            break;

        case Template::T3_XorAddXor:
            for (size_t i = 0; i < n; ++i)
                out[i] = crypto::t3::decrypt(enc[i], info->k1, info->k2, info->k3);
            break;

        case Template::T4_TlsSubXor: {
            uint64_t tls_val = snap.qword(info->tls_off);
            for (size_t i = 0; i < n; ++i)
                out[i] = (enc[i] - tls_val) ^ info->k1;
            break;
        }

        case Template::T7_TlsRotSingleXor:
            for (size_t i = 0; i < n; ++i)
                out[i] = crypto::t7::decrypt(enc[i], info->k1, info->tls_off, snap);
            break;

        default:
            // Fallback — go through the single-shot dispatch.
            for (size_t i = 0; i < n; ++i) {
                auto r = decrypt(site, enc[i]);
                out[i] = r.ok ? r.plain : 0;
            }
            break;
    }
}

Result32 decrypt_health(const void* dmg_comp) {
    if (!dmg_comp) return Result32::fail();
    // Route through T5 directly.
    auto s = crypto::t5::decrypt(dmg_comp);
    return Result32::of(static_cast<uint32_t>(s));
}

} // namespace crypto

// ── C ABI exports ──────────────────────────────────────────────────

extern "C" {

int siege_crypto_init(void* module_base, void* tls_index_ptr) {
    return crypto::init(reinterpret_cast<uint64_t>(module_base),
                         reinterpret_cast<uint32_t*>(tls_index_ptr)) ? 0 : 1;
}

unsigned long long siege_crypto_decrypt(unsigned int site,
                                          unsigned long long enc,
                                          int* ok) {
    auto r = crypto::decrypt(static_cast<crypto::SiteId>(site), enc);
    if (ok) *ok = r.ok ? 1 : 0;
    return r.plain;
}

unsigned int siege_crypto_decrypt_health(const void* dmg_comp, int* ok) {
    auto r = crypto::decrypt_health(dmg_comp);
    if (ok) *ok = r.ok ? 1 : 0;
    return r.plain;
}

int siege_crypto_dump_sites(char* buf, int buf_len) {
    if (!buf || buf_len <= 0) return 0;
    int written = 0;
    for (size_t i = 0; i < crypto::site_count(); ++i) {
        const crypto::SiteInfo* s = crypto::site_at(i);
        if (!s) continue;
        int n = snprintf(buf + written, buf_len - written,
                          "%u %u %llX %llX %llX %X %s\n",
                          static_cast<unsigned>(s->id),
                          static_cast<unsigned>(s->tmpl),
                          (unsigned long long)s->k1,
                          (unsigned long long)s->k2,
                          (unsigned long long)s->k3,
                          s->tls_off,
                          s->name ? s->name : "");
        if (n <= 0 || written + n >= buf_len) break;
        written += n;
    }
    return written;
}

} // extern "C"
