// crypto/decrypt_t5.h — Template T5: HealthState decrypt.
//
// The 32-bit encrypted HealthState lives at DamageComponent+0x184.
// Algorithm verified against the live game via Bytecode's
// /r6_decrypt_health endpoint (recon MD §9).
//
//     enc[4] bytes at DamageComponent+0x184
//     key   = TLS[0x3C80]      (64-bit)
//     rot   = TLS[0x3A50]      (32-bit; low 5 bits used)
//     const = 0x4AB53B9A
//
//     raw = XOR bytewise with (key >> i*8) for i=0..3
//     raw = raw - const
//     if (rot & 0x1F) != 0: raw = ROR32(raw, rot & 0x1F)
//     return raw as HealthState enum:
//         3 = DBNO, 4 = dead, 0..2 = alive/injured
#pragma once
#include "types.h"
#include "tls.h"

namespace crypto::t5 {

constexpr uint32_t SUB_CONST      = 0x4AB53B9AU;
constexpr uint32_t TLS_KEY_OFF    = 0x3C80;
constexpr uint32_t TLS_ROT_OFF    = 0x3A50;

// Enum for the decoded state (as observed in live decodes).
enum class HealthState : uint32_t {
    Alive    = 0,
    Injured1 = 1,
    Injured2 = 2,
    DBNO     = 3,
    Dead     = 4,
    // higher values seen occasionally in transient states
};

__forceinline uint32_t decrypt_raw(const uint8_t enc[4]) noexcept {
    crypto::tls::Snapshot snap;
    if (!snap.valid()) return 0;
    uint64_t key = snap.qword(TLS_KEY_OFF);
    uint32_t rot = snap.dword(TLS_ROT_OFF);
    uint32_t raw = 0;
    for (int i = 0; i < 4; ++i) {
        uint8_t k = static_cast<uint8_t>((key >> (i * 8)) & 0xFF);
        raw |= static_cast<uint32_t>(enc[i] ^ k) << (i * 8);
    }
    raw = (raw - SUB_CONST);
    uint32_t r = rot & 0x1F;
    if (r != 0) raw = crypto::rotr32(raw, r);
    return raw;
}

// Convenience: read the 4 encrypted bytes at damage_comp + 0x184.
__forceinline HealthState decrypt(const void* damage_comp) noexcept {
    if (!damage_comp) return HealthState::Alive;
    const uint8_t* enc = reinterpret_cast<const uint8_t*>(damage_comp) + 0x184;
    return static_cast<HealthState>(decrypt_raw(enc));
}

inline const char* to_string(HealthState s) noexcept {
    switch (s) {
        case HealthState::Alive:    return "Alive";
        case HealthState::Injured1: return "Injured1";
        case HealthState::Injured2: return "Injured2";
        case HealthState::DBNO:     return "DBNO";
        case HealthState::Dead:     return "Dead";
        default:                    return "Unknown";
    }
}

} // namespace crypto::t5
