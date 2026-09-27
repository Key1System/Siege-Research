// crypto/decrypt_t4.h — Template T4: TLS-subtracted, XORed with constant.
//
// Formula:  plain = (globalEnc - TLS[SITE_TLS_OFF]) ^ K1
//
// Used for `.data`-resident globally-encrypted pointers (engine
// singletons that need to survive across threads). The encrypted value
// itself lives at a fixed VA in the game module; only the TLS key and
// K1 are needed to decrypt.
//
// Reference:
//     mov ecx, [TlsIndex]
//     mov r9,  gs:[0x58]
//     mov r9,  [r9+rcx*8]
//     mov r9,  [r9+0x9370]         ; TLS key
//     mov rax, [Game.exe+GLOBAL]   ; encrypted qword
//     sub rax, r9
//     mov r9,  <K1>
//     xor r9,  rax                 ; plaintext
#pragma once
#include "types.h"
#include "tls.h"

namespace crypto::t4 {

// Decrypt with an already-read global ciphertext value.
__forceinline uint64_t decrypt(uint64_t enc_global,
                                uint32_t tls_off, uint64_t k1) noexcept {
    return (enc_global - crypto::tls::read_qword(tls_off)) ^ k1;
}

__forceinline uint64_t decrypt(uint64_t enc_global,
                                uint32_t tls_off, uint64_t k1,
                                const crypto::tls::Snapshot& snap) noexcept {
    return (enc_global - snap.qword(tls_off)) ^ k1;
}

// Convenience: read the global ciphertext ourselves.
__forceinline uint64_t decrypt_at(const uint64_t* enc_global_addr,
                                    uint32_t tls_off, uint64_t k1) noexcept {
    if (!enc_global_addr) return 0;
    return decrypt(*enc_global_addr, tls_off, k1);
}

// Symmetric inverse.
__forceinline uint64_t encrypt(uint64_t plain,
                                uint32_t tls_off, uint64_t k1) noexcept {
    return (plain ^ k1) + crypto::tls::read_qword(tls_off);
}

} // namespace crypto::t4
