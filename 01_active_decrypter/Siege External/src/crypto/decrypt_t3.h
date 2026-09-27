// crypto/decrypt_t3.h — Template T3: Pure 3-key XOR-ADD-XOR.
//
// Formula:  plain = ((enc ^ K1) + K2) ^ K3
//
// Each T3 site has its own K1/K2/K3 triple, extracted from the site's
// disassembly. The decrypter class takes them as arguments so one
// implementation handles every site.
//
// Reference (user-provided reference build, decrypting World*):
//     mov r9,  <K1>
//     xor r9,  [r12+18]      ; enc from RecordingManager
//     mov rax, <K2>
//     add rax, r9            ; (enc ^ K1) + K2
//     mov r15, <K3>
//     xor r15, rax           ; plaintext
#pragma once
#include "types.h"

namespace crypto::t3 {

__forceinline uint64_t decrypt(uint64_t enc,
                                uint64_t k1, uint64_t k2, uint64_t k3) noexcept {
    return ((enc ^ k1) + k2) ^ k3;
}

// Symmetric inverse for the write path.
__forceinline uint64_t encrypt(uint64_t plain,
                                uint64_t k1, uint64_t k2, uint64_t k3) noexcept {
    return ((plain ^ k3) - k2) ^ k1;
}

} // namespace crypto::t3
