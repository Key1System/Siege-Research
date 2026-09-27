// crypto/decrypt_t7.h — Template T7: TLS-rotated single-XOR.
//
// Formula:  plain = ROR( enc XOR K, TLS[SITE_TLS_OFF] & 63 )
//
// This is the SIMPLEST TLS-crypto template in R6: a single 64-bit
// constant XORed with the encrypted value, then ROR by a TLS-derived
// amount. 15+ sites in the binary use this template — some share the
// same K, others have per-site K. TLS offset varies per site.
//
// Reference (sub_7FF6FF4631A0 site):
//     mov rax, [r9+0x10]                 ; enc
//     mov rcx, 0x8D4BFDA3932A12A6        ; K
//     xor rax, rcx
//     mov r8d, cs:TlsIndex
//     mov rcx, gs:58h
//     mov rcx, [rcx+r8*8]
//     mov rcx, [rcx+0x61B8]              ; rot amount
//     ror rax, cl                        ; plaintext
//
// Known K values in the binary (2026-07-17):
//     0x8D4BFDA3932A12A6   — 7 sites
//     0xAC3ABBDFA62139B3   — 3 sites
//     0xE254A110CC48D136   — 2 sites
//     0xD003DDA5FEEB8742   — 1 site
//     0x0583B5946C19DD66   — 2 sites
//     0x1EBBBEEBE9584A28   — 1 site
#pragma once
#include "types.h"
#include "tls.h"

namespace crypto::t7 {

__forceinline uint64_t decrypt(uint64_t enc,
                                uint64_t k,
                                uint32_t tls_off) noexcept {
    return crypto::rotr64(enc ^ k, crypto::tls::rot_amount(tls_off));
}

__forceinline uint64_t decrypt(uint64_t enc,
                                uint64_t k,
                                uint32_t tls_off,
                                const crypto::tls::Snapshot& snap) noexcept {
    return crypto::rotr64(enc ^ k, snap.rot(tls_off));
}

__forceinline uint64_t encrypt(uint64_t plain,
                                uint64_t k,
                                uint32_t tls_off) noexcept {
    return crypto::rotl64(plain, crypto::tls::rot_amount(tls_off)) ^ k;
}

} // namespace crypto::t7
