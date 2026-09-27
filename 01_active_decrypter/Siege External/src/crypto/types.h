// crypto/types.h — public types for the R6 decrypter library.
//
// The decrypter runs inside RainbowSix.exe as an internal DLL. Every
// crypto site in the game is identified by a `SiteId` from the enum
// below; the decrypter table maps each SiteId to the template (T1..T6)
// that site uses and the site-specific constants.
//
// See CRYPTO_MAP.md for the theory.
#pragma once
#include <cstdint>

namespace crypto {

// One entry per template family we know about. Keep in sync with the
// tables in site_registry.h.
enum class Template : uint8_t {
    Invalid = 0,
    T1_TlsRotMbaPure,        // ROR((enc^K1)+K2, TLS[off])
    T2_StackHashedMba,       // via in-process trampoline into game code
    T3_XorAddXor,            // ((enc^K1)+K2)^K3
    T4_TlsSubXor,            // (globalEnc - TLS[off]) ^ K1
    T5_HealthState,          // HealthState 32-bit decrypt
    T6_AnvilHandle,          // AnvilClassRegistry table walk
    T7_TlsRotSingleXor,      // ROR(enc ^ K, TLS[off])  — 15+ sites
};

// Stable identifier for every crypto site we support. Human-readable
// name reflects the semantic use of the decrypted value, not the
// instruction address (addresses shift across R6 patches; semantics
// don't).
enum class SiteId : uint32_t {
    Invalid = 0,

    // T1 — TLS-rotated MBA (pure constants)
    T1_PhysicsStepWorld    = 1001,   // hknp_PhysicsStep_A world*
    T1_UnknownCallback     = 1002,   // sub_7FF700F21C90

    // T3 — 3-key XOR-ADD-XOR (populated as sites are discovered)
    T3_WorldPointer        = 3001,   // reference example from user
    // ...more added by grep

    // T4 — TLS-subtracted XOR (populated as sites are discovered)
    T4_UnknownGlobalA      = 4001,   // reference example from user
    // ...more added by grep

    // T5 — HealthState
    T5_HealthState         = 5001,

    // T6 — Anvil handle resolve
    T6_AnvilResolve        = 6001,

    // T7 — TLS-rotated single-XOR (site addresses in IDB, this build)
    T7_Site_FF4634D4       = 7001,
    T7_Site_FF463614       = 7002,
    T7_Site_FF4638A4       = 7003,
    T7_Site_FF4639E4       = 7004,
    T7_Site_FFB1DBCD       = 7005,
    T7_Site_06B3A9A8       = 7006,
    T7_Site_030ADAF6       = 7007,
    T7_Site_FDED1AAF       = 7008,
    T7_Site_FEEDDAF8       = 7009,
    T7_Site_0747349F       = 7010,
    T7_Site_FCDBB988       = 7011,
    T7_Site_048ABD37       = 7012,
    T7_Site_048AC077       = 7013,
    T7_Site_048AC17B       = 7014,
    T7_Site_07D3D973       = 7015,
    T7_Site_FCFB519A       = 7016,   // K=0xE254A110CC48D136, TLS=0x20F8

    // T2 sites are addressed by their raw instruction address at
    // runtime — no compile-time enum needed since we use trampolines.
};

struct Result {
    uint64_t plain = 0;
    bool     ok    = false;

    static Result fail() { return {}; }
    static Result of(uint64_t v) { return { v, true }; }
};

// 32-bit result variant (HealthState + similar).
struct Result32 {
    uint32_t plain = 0;
    bool     ok    = false;

    static Result32 fail() { return {}; }
    static Result32 of(uint32_t v) { return { v, true }; }
};

// Site metadata — one row per SiteId, held in site_registry.h.
struct SiteInfo {
    SiteId       id;
    Template     tmpl;
    // Per-template constants (interpretation depends on tmpl).
    uint64_t     k1 = 0;
    uint64_t     k2 = 0;
    uint64_t     k3 = 0;
    // TLS offset used (T1, T4, T5). Ignored for T3.
    uint32_t     tls_off = 0;
    // Human-readable name / description (for logging + test names).
    const char*  name = "unknown";
};

// Compile-time byte utilities (widely used across the templates).
constexpr uint64_t rotr64(uint64_t v, uint32_t n) noexcept {
    n &= 63;
    return (v >> n) | (v << ((64 - n) & 63));
}
constexpr uint64_t rotl64(uint64_t v, uint32_t n) noexcept {
    n &= 63;
    return (v << n) | (v >> ((64 - n) & 63));
}
constexpr uint32_t rotr32(uint32_t v, uint32_t n) noexcept {
    n &= 31;
    return (v >> n) | (v << ((32 - n) & 31));
}
constexpr uint32_t rotl32(uint32_t v, uint32_t n) noexcept {
    n &= 31;
    return (v << n) | (v >> ((32 - n) & 31));
}

} // namespace crypto
