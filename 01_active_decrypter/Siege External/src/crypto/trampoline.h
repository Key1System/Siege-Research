// crypto/trampoline.h — T2 in-process trampoline.
//
// T2 sites synthesize their crypto polynomial from the runtime stack
// address of local variables, so we can't invert them analytically. But
// running inside the game process, we CAN jump into the game's own
// decrypt code, let it run, and harvest the plaintext.
//
// Strategy: for each T2 site we know about, install a small stub that:
//   1. Calls the game function containing the crypto site with an
//      argument setup where the "input" struct field holds our
//      ciphertext.
//   2. The crypto runs on real stack — game's own MBA polynomial fires
//      identically to how it does for any legitimate caller.
//   3. Result is captured either as the function's return value or by
//      reading a struct field the game function wrote to.
//
// This file provides:
//   - Trampoline<Ret, Args...>: generic caller helper.
//   - Registered T2 site helpers (one per meaningful T2 site).
//
// Constraints:
//   - The game function must be safe to invoke (no side effects on
//     shared game state). Typically the smallest possible container:
//     a getter that reads an encrypted qword and returns the plain.
//   - If the function doesn't exist as a clean getter, we can also
//     synthesize a wrapper: allocate a temporary struct, poke the
//     ciphertext into the exact offset the game function reads from,
//     call the getter with that struct.
//
// Not implementing every T2 site up-front — this is the framework. Add
// concrete site helpers when we identify a meaningful T2 value to
// decrypt (typically encrypted per-instance pointers on components).
#pragma once
#include "types.h"
#include <cstdint>

namespace crypto::trampoline {

// Generic caller: takes a resolved game-function pointer plus its args
// and returns the game's own return value. Use for T2 sites that expose
// a clean "getter" ABI.
template <typename Ret, typename... Args>
__forceinline Ret call(void* fn, Args... args) noexcept {
    using Fn = Ret(__fastcall*)(Args...);
    return reinterpret_cast<Fn>(fn)(args...);
}

// Helper for the common R6 shape: a getter that takes a struct pointer
// as arg0 and reads the encrypted qword at struct+field_off. To decrypt
// an arbitrary ciphertext with this site's algorithm, we allocate a
// stack-local dummy struct, write the ciphertext at the right offset,
// call the getter.
//
// NOTE: only safe when the getter is verified to read ONLY the
// field_off qword. If the getter touches other fields, this segfaults.
template <int FIELD_OFF>
struct StructGetterProbe {
    // Dummy struct large enough to contain FIELD_OFF+8. Zero-initialized.
    uint8_t buf[FIELD_OFF + 32];

    __forceinline void set_enc(uint64_t enc) noexcept {
        *reinterpret_cast<uint64_t*>(buf + FIELD_OFF) = enc;
    }
};

// The prototype for a T2-site probe function: takes a ciphertext, uses
// the game's own code to invert it, returns plaintext.
using T2ProbeFn = uint64_t (*)(uint64_t enc) noexcept;

// Registry of installed T2 probes. Grows as we identify T2 sites we
// want to decrypt.
struct T2Site {
    const char*  name;
    void*        game_fn_addr;   // resolved by sig scan at DLL load
    int          field_off;
    T2ProbeFn    probe;          // populated by the installer
};

// Called by dllmain after resolving addresses.
void install_probes(uint64_t module_base) noexcept;

// Public entry: decrypt via a specific T2 site.
Result decrypt(const char* site_name, uint64_t enc);

} // namespace crypto::trampoline
