// crypto/site_registry.cpp — the site table.
//
// Add rows here when a new site is characterised. Constants come from
// IDA disasm (movabs imm64). TLS offsets come from the `[reg+IMM32]`
// load right after the ROR-key fetch.
//
// Naming: use the semantic role of the value (`PhysicsStepWorld`), not
// the IDB address (`sub_7FF6FF6F6C10`) — addresses shift across patches
// but semantics don't.
//
// T7 rows populated 2026-07-17 from a full IDB grep against build
// `RainbowSix_dump.exe.i64` (IDB base 0x7FF6FBEB0000). Constants
// extracted from each site's `movabs r, imm64 / xor r, r / TLS load`
// block. See CRYPTO_MAP.md §3.x for the template details.
#include "site_registry.h"

namespace crypto {

// clang-format off
static const SiteInfo kSites[] = {
    // ── T1 — TLS-rotated MBA (pure constants) ────────────────────────
    // Both known sites share K1/K2; only TLS offset varies.
    { SiteId::T1_PhysicsStepWorld,   Template::T1_TlsRotMbaPure,
      /*k1*/ 0x801DE0677929AF10ULL, /*k2*/ 0x758BFE7BAD72DEF7ULL, /*k3*/ 0,
      /*tls_off*/ 0x6FB8,
      "T1: hknp_PhysicsStep_A world pointer" },

    { SiteId::T1_UnknownCallback,    Template::T1_TlsRotMbaPure,
      0x801DE0677929AF10ULL, 0x758BFE7BAD72DEF7ULL, 0,
      0x9C40,
      "T1: sub_7FF700F21C90 callback" },

    // ── T3 — 3-key XOR-ADD-XOR ───────────────────────────────────────
    // Reference site from user (World* decrypt in a newer R6 build).
    // K1/K2/K3 will be filled in per-build as we identify them; leave
    // zeros as a sentinel until then.
    { SiteId::T3_WorldPointer,       Template::T3_XorAddXor,
      0, 0, 0,
      0,
      "T3: World* pointer (placeholder — populate K1/K2/K3 per-build)" },

    // ── T4 — TLS-subtracted XOR ──────────────────────────────────────
    { SiteId::T4_UnknownGlobalA,     Template::T4_TlsSubXor,
      /*k1*/ 0, 0, 0,
      /*tls_off*/ 0x9370,
      "T4: reference site (populate K1 per-build)" },

    // ── T5 — HealthState ─────────────────────────────────────────────
    { SiteId::T5_HealthState,        Template::T5_HealthState,
      0, 0, 0,
      0,
      "T5: DamageComponent+0x184 HealthState" },

    // ── T6 — Anvil handle ────────────────────────────────────────────
    { SiteId::T6_AnvilResolve,       Template::T6_AnvilHandle,
      0, 0, 0,
      0,
      "T6: AnvilClassRegistry handle resolve" },

    // ── T7 — TLS-rotated single-XOR ──────────────────────────────────
    // Formula: plain = ROR( enc XOR K, TLS[tls_off] & 63 )
    // K stored in k1; k2/k3 unused. 16 sites extracted from full IDB
    // sweep. Some sites share the same K (typical of R6's compile-time
    // template instantiation for related decrypt sites).
    { SiteId::T7_Site_FF4634D4,      Template::T7_TlsRotSingleXor,
      /*k1*/ 0x8D4BFDA3932A12A6ULL, 0, 0,
      /*tls_off*/ 0x61B8,
      "T7: sub_7FF6FF4631A0 @ 0xFF4634D4 (K=8D4B, TLS=61B8)" },

    { SiteId::T7_Site_FF463614,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0x61B8,
      "T7: sub_7FF6FF4631A0 @ 0xFF463614 (K=8D4B, TLS=61B8)" },

    { SiteId::T7_Site_FF4638A4,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0x61B8,
      "T7: sub_7FF6FF4631A0 @ 0xFF4638A4 (K=8D4B, TLS=61B8)" },

    { SiteId::T7_Site_FF4639E4,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0x61B8,
      "T7: sub_7FF6FF4631A0 @ 0xFF4639E4 (K=8D4B, TLS=61B8)" },

    { SiteId::T7_Site_FFB1DBCD,      Template::T7_TlsRotSingleXor,
      0xAC3ABBDFA62139B3ULL, 0, 0,
      0x7578,
      "T7: @ 0xFFB1DBCD (K=AC3A, TLS=7578)" },

    { SiteId::T7_Site_06B3A9A8,      Template::T7_TlsRotSingleXor,
      0xE254A110CC48D136ULL, 0, 0,
      0x11240,
      "T7: @ 0x06B3A9A8 (K=E254, TLS=11240)" },

    { SiteId::T7_Site_030ADAF6,      Template::T7_TlsRotSingleXor,
      0xAC3ABBDFA62139B3ULL, 0, 0,
      0x0,   // TLS offset not extracted in the session sample; needs re-verify
      "T7: @ 0x030ADAF6 (K=AC3A, TLS=?)" },

    { SiteId::T7_Site_FDED1AAF,      Template::T7_TlsRotSingleXor,
      0x1EBBBEEBE9584A28ULL, 0, 0,
      0x0,   // TLS offset variant load; needs re-verify
      "T7: @ 0xFDED1AAF (K=1EBB, TLS=?)" },

    { SiteId::T7_Site_FEEDDAF8,      Template::T7_TlsRotSingleXor,
      0xD003DDA5FEEB8742ULL, 0, 0,
      0x5F00,
      "T7: @ 0xFEEDDAF8 (K=D003, TLS=5F00)" },

    { SiteId::T7_Site_0747349F,      Template::T7_TlsRotSingleXor,
      0x0583B5946C19DD66ULL, 0, 0,
      0x11830,
      "T7: @ 0x0747349F (K=0583, TLS=11830)" },

    { SiteId::T7_Site_FCDBB988,      Template::T7_TlsRotSingleXor,
      0x0583B5946C19DD66ULL, 0, 0,
      0x1B88,
      "T7: @ 0xFCDBB988 (K=0583, TLS=1B88)" },

    { SiteId::T7_Site_048ABD37,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0xEC70,
      "T7: @ 0x048ABD37 (K=8D4B, TLS=EC70)" },

    { SiteId::T7_Site_048AC077,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0xEC70,
      "T7: @ 0x048AC077 (K=8D4B, TLS=EC70)" },

    { SiteId::T7_Site_048AC17B,      Template::T7_TlsRotSingleXor,
      0x8D4BFDA3932A12A6ULL, 0, 0,
      0xEC70,
      "T7: @ 0x048AC17B (K=8D4B, TLS=EC70)" },

    { SiteId::T7_Site_07D3D973,      Template::T7_TlsRotSingleXor,
      0xAC3ABBDFA62139B3ULL, 0, 0,
      0x11E20,
      "T7: @ 0x07D3D973 (K=AC3A, TLS=11E20)" },

    { SiteId::T7_Site_FCFB519A,      Template::T7_TlsRotSingleXor,
      0xE254A110CC48D136ULL, 0, 0,
      0x20F8,
      "T7: @ 0xFCFB519A (K=E254, TLS=20F8)" },
};
// clang-format on

const SiteInfo* find_site(SiteId id) noexcept {
    for (const auto& s : kSites) {
        if (s.id == id) return &s;
    }
    return nullptr;
}

size_t site_count() noexcept {
    return sizeof(kSites) / sizeof(kSites[0]);
}

const SiteInfo* site_at(size_t idx) noexcept {
    if (idx >= site_count()) return nullptr;
    return &kSites[idx];
}

} // namespace crypto
