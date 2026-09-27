// crypto/decrypt_t1.h — Template T1: TLS-rotated MBA with pure constants.
//
// Formula:  plain = ROR( (enc ^ K1) + K2, TLS[SITE_TLS_OFF] & 63 )
//
// Both observed T1 sites in the analysed R6 build use identical MBA
// constants; only the TLS rotate offset varies. So one function fits all
// of T1 — pass the encrypted qword, the site's TLS offset, and (for
// speed) an already-fetched TLS snapshot.
//
// Reference (hknp_PhysicsStep_A):
//     mov rcx, 0x801DE0677929AF10   ; K1
//     xor rcx, [rdx+38h]            ; enc
//     mov rdx, 0x758BFE7BAD72DEF7   ; K2
//     add rdx, rcx
//     mov r8d, cs:TlsIndex
//     mov rcx, gs:58h
//     mov rcx, [rcx+r8*8]
//     mov rcx, [rcx+0x6FB8]         ; rot amount
//     ror rdx, cl                   ; plaintext in rdx
#pragma once
#include "types.h"
#include "tls.h"

namespace crypto::t1 {

// Fixed MBA constants (identical at both known T1 sites in R6 build
// 0x7FF6FBEB0000). If a future R6 patch introduces a new T1 site with
// different constants, we make a per-site variant instead.
constexpr uint64_t K1 = 0x801DE0677929AF10ULL;
constexpr uint64_t K2 = 0x758BFE7BAD72DEF7ULL;

__forceinline uint64_t decrypt(uint64_t enc, uint32_t tls_off) noexcept {
    uint64_t x = (enc ^ K1) + K2;
    return crypto::rotr64(x, crypto::tls::rot_amount(tls_off));
}

// Snapshot form — avoid re-reading TLS block for hot loops.
__forceinline uint64_t decrypt(uint64_t enc, uint32_t tls_off,
                                const crypto::tls::Snapshot& snap) noexcept {
    uint64_t x = (enc ^ K1) + K2;
    return crypto::rotr64(x, snap.rot(tls_off));
}

// Symmetric inverse for encryption (write path — used only if we ever
// need to poke a value back). Not used in read-only tools but kept for
// completeness and symmetry-tests in the harness.
__forceinline uint64_t encrypt(uint64_t plain, uint32_t tls_off) noexcept {
    uint8_t rot = crypto::tls::rot_amount(tls_off);
    return (crypto::rotl64(plain, rot) - K2) ^ K1;
}

} // namespace crypto::t1
